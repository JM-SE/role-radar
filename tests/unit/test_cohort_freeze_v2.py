"""Offline amendment-v2 contract checks; no live database or network access."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from role_radar.evaluation.cohort_freeze.bundle_store import V2BundleStore
from role_radar.evaluation.cohort_freeze.contracts import (
    BoundaryResolution,
    CandidateEvidence,
    CorpusResult,
    DeploymentIdentity,
    RepositorySnapshot,
)
from role_radar.evaluation.cohort_freeze.materialization import materialize_v2
from role_radar.evaluation.cohort_freeze.partition import partition_corpus
from role_radar.evaluation.cohort_freeze.policy import (
    ALEMBIC_HEAD,
    BASELINE_PROFILE_ID,
    BASELINE_PROFILE_SHA256,
    CORPUS_COUNT,
    HOLDOUT_COUNT,
    LOWER_BOUNDARY_RUN_ID,
    PILOT_COUNT,
    UPPER_BOUNDARY_RUN_ID,
    acknowledgement_v2,
)
from role_radar.evaluation.cohort_freeze.runtime import CohortFreezeRuntimeV2, RuntimeErrorCode
from role_radar.evaluation.cohort_freeze.selection import build_bounded_corpus
from tests.unit.test_cohort_freeze_gate_a import candidate


def _corpus() -> CorpusResult:
    values = tuple(
        replace(candidate(index), run_created_count=CORPUS_COUNT, run_observed_count=CORPUS_COUNT)
        for index in range(CORPUS_COUNT)
    )
    return build_bounded_corpus(
        values,
        boundaries={"lower": LOWER_BOUNDARY_RUN_ID, "upper": UPPER_BOUNDARY_RUN_ID},
        bounded_fingerprint_sha256="b" * 64,
    )


def _snapshot(candidates: Iterable[CandidateEvidence]) -> RepositorySnapshot:
    return RepositorySnapshot(
        boundary=BoundaryResolution(LOWER_BOUNDARY_RUN_ID, "2026-08-01T00:00:00Z", "completed"),
        fingerprint="b" * 64,
        deployment={},
        runs=(),
        operations=(),
        links=(),
        jobs=(),
        identities=(),
        profile={
            "id": BASELINE_PROFILE_ID,
            "version": 2,
            "schema_version": 1,
            "sha256": BASELINE_PROFILE_SHA256,
        },
        alembic_version=ALEMBIC_HEAD,
        candidates=tuple(candidates),
        upper_boundary=BoundaryResolution(
            UPPER_BOUNDARY_RUN_ID, "2026-08-21T00:00:00Z", "completed"
        ),
        bounded_fingerprint_sha256="b" * 64,
    )


def test_v2_is_exact_partition_and_permutation_invariant() -> None:
    first = _corpus()
    second = build_bounded_corpus(
        tuple(item.evidence for item in reversed(first.items)),
        boundaries={"lower": LOWER_BOUNDARY_RUN_ID, "upper": UPPER_BOUNDARY_RUN_ID},
        bounded_fingerprint_sha256="b" * 64,
    )
    first_partition = partition_corpus(first)
    second_partition = partition_corpus(second)
    assert first.corpus_sha256 == second.corpus_sha256
    assert len(first.items) == CORPUS_COUNT
    assert len(first_partition.pilot) == PILOT_COUNT
    assert len(first_partition.holdout) == HOLDOUT_COUNT
    assert first_partition.pilot_sha256 == second_partition.pilot_sha256
    assert {item.item_semantic_sha256 for item in first_partition.pilot}.isdisjoint(
        item.item_semantic_sha256 for item in first_partition.holdout
    )


def test_v2_ack_shape_rejects_historical_ack() -> None:
    corpus = _corpus()
    partition = partition_corpus(corpus)
    ack = acknowledgement_v2(
        preview_sha256="a" * 64,
        corpus_sha256=corpus.corpus_sha256 or "",
        pilot_sha256=partition.pilot_sha256,
        holdout_sha256=partition.holdout_sha256,
    )
    assert "FREEZE F10.1C V2" in ack
    assert "protocol=f10.1c-selection-v1" not in ack


def test_v2_bundle_has_six_files_and_detects_tamper(tmp_path: Path) -> None:
    corpus = _corpus()
    partition = partition_corpus(corpus)
    files, internal, dataset_id = materialize_v2(
        _snapshot(item.evidence for item in corpus.items),
        corpus,
        partition,
        deployment=DeploymentIdentity("a" * 40, True, ALEMBIC_HEAD),
    )
    store = V2BundleStore(tmp_path / "private")
    target = store.publish(dataset_id=dataset_id, file_payloads=files, internal=internal)
    assert {item.name for item in target.iterdir()} == {
        "corpus.jsonl",
        "provenance.jsonl",
        "pilot-label-view.jsonl",
        "holdout-label-view.jsonl",
        "internal-manifest.json",
        "checksums.sha256",
    }
    assert store.verify(dataset_id)
    (target / "holdout-label-view.jsonl").write_bytes(b"tampered\n")
    assert not store.verify(dataset_id)


def test_v2_runtime_rejects_v1_ack_before_publish(tmp_path: Path) -> None:
    corpus = _corpus()
    repository = type(
        "Repo",
        (),
        {"load": lambda _self: _snapshot(item.evidence for item in corpus.items)},
    )()
    runtime = CohortFreezeRuntimeV2(
        repository,
        V2BundleStore(tmp_path / "private"),
        deployment=DeploymentIdentity("a" * 40, True, ALEMBIC_HEAD),
    )
    try:
        runtime.freeze("FREEZE F10.1C preview_sha256=" + "a" * 64)
    except RuntimeErrorCode as exc:
        assert exc.code == "acknowledgement_mismatch"
    else:
        raise AssertionError("v1 acknowledgement unexpectedly accepted")


def test_upper_aggregate_contract_uses_run_counters_not_link_dispositions() -> None:
    """Stale observations are run counters, not run-job link dispositions."""

    from role_radar.evaluation.cohort_freeze.repository import _upper_aggregate_valid

    upper = {
        "created_count": 151,
        "duplicate_count": 22,
        "stale_count": 255,
        "invalid_count": 0,
        "conflict_count": 0,
        "observed_count": 428,
    }
    links = tuple({"disposition": "created"} for _ in range(151)) + tuple(
        {"disposition": "duplicate"} for _ in range(22)
    )

    assert _upper_aggregate_valid(upper, links)
    assert not _upper_aggregate_valid({**upper, "stale_count": 254}, links)
