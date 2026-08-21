"""Offline Gate-A coverage for the F10.1C pure/runtime boundaries."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from role_radar.cli.main import _parser
from role_radar.evaluation.cohort_freeze.contracts import (
    BoundaryResolution,
    CandidateEvidence,
    DeploymentIdentity,
    IdentityEvidence,
    RepositorySnapshot,
)
from role_radar.evaluation.cohort_freeze.materialization import materialize
from role_radar.evaluation.cohort_freeze.policy import (
    ALEMBIC_HEAD,
    BASELINE_PROFILE_ID,
    BASELINE_PROFILE_SCHEMA,
    BASELINE_PROFILE_SHA256,
    BASELINE_PROFILE_VERSION,
    BOUNDARY_RUN_ID,
    acquisition_snapshot_hash,
    canonical_hash,
)
from role_radar.evaluation.cohort_freeze.repository import SQLiteSnapshotRepository
from role_radar.evaluation.cohort_freeze.runtime import CohortFreezeRuntime, acknowledgement
from role_radar.evaluation.cohort_freeze.selection import select_candidates
from role_radar.evaluation.snapshot_store import SnapshotStore


def candidate(index: int, *, job_id: str | None = None) -> CandidateEvidence:
    source_id = f"source-{index}"
    source = {
        "source_id": source_id,
        "source_key": f"source:key:{index}",
        "type": "greenhouse",
        "revision": 1,
    }
    identity_value = f"greenhouse:external:{index}"
    identity = IdentityEvidence(
        "source_external_id",
        "strong-identity-v1",
        identity_value,
        hashlib.sha256(identity_value.encode()).hexdigest(),
        job_id or f"job-{index}",
    )
    return CandidateEvidence(
        run_id="run-1",
        run_started_at="2026-08-01T00:00:00Z",
        run_state="completed",
        run_policy_version="continuous-acquisition-v1",
        run_snapshot_json=[source],
        run_snapshot_hash=canonical_hash([source]),
        link_id=f"link-{index}",
        operation_id=f"operation-{index}",
        job_id=job_id or f"job-{index}",
        disposition="created",
        operation_run_id="run-1",
        operation_source_id=source_id,
        operation_result_state="succeeded",
        operation_finished_at="2026-08-01T00:01:00Z",
        operation_created_count=1,
        operation_observed_count=1,
        run_created_count=100,
        run_observed_count=100,
        source_snapshot_json=source,
        accepted_observation_at=datetime(2026, 8, 1, tzinfo=UTC),
        provider_recency_at=datetime(2026, 8, 1, tzinfo=UTC),
        recency_semantic="published_at",
        freshness_policy_version="freshness-v1",
        identity_policy_version="strong-identity-v1",
        provenance_hash="a" * 64,
        title=f"Title {index}",
        company="Company",
        location="Remote",
        description=f"Description {index}",
        application_url=None,
        identity_keys=(identity,),
        source_type="greenhouse",
    )


def snapshot(candidates: tuple[CandidateEvidence, ...]) -> RepositorySnapshot:
    return RepositorySnapshot(
        boundary=BoundaryResolution(BOUNDARY_RUN_ID, "2026-08-01T00:00:00Z", "completed"),
        fingerprint="b" * 64,
        deployment={},
        runs=(),
        operations=(),
        links=(),
        jobs=(),
        identities=(),
        profile={
            "id": BASELINE_PROFILE_ID,
            "version": BASELINE_PROFILE_VERSION,
            "schema_version": BASELINE_PROFILE_SCHEMA,
            "sha256": BASELINE_PROFILE_SHA256,
        },
        alembic_version=ALEMBIC_HEAD,
        candidates=candidates,
    )


@pytest.mark.parametrize("count", [0, 26, 49])
def test_waiting_has_no_selection(count: int) -> None:
    result = select_candidates(candidate(index) for index in range(count))
    assert result.status == "waiting"
    assert result.selected_count == 0
    assert result.selection_sha256 is None


def test_ready_selects_total_order_and_is_permutation_invariant() -> None:
    values = tuple(candidate(index) for index in range(55))
    first = select_candidates(values)
    second = select_candidates(reversed(values))
    assert first.status == "ready"
    assert first.selected_count == 50
    assert [item.link_id for item in first.selected] == [item.link_id for item in second.selected]
    assert first.candidate_cohort_sha256 == second.candidate_cohort_sha256
    assert first.rejection_counts["eligible_after_first_50"] == 5


def test_precedence_rejects_invalid_provenance_and_content() -> None:
    invalid_provenance = replace(candidate(1), provenance_hash="not-a-hash")
    invalid_content = replace(candidate(2), title="   ")
    result = select_candidates((invalid_provenance, invalid_content))
    assert result.rejection_counts == {
        "freshness_provenance_invalid": 1,
        "job_content_missing": 1,
    }


def test_snapshot_hash_is_compatible_with_multi_source_acquisition_order() -> None:
    first = {
        "source_id": "source-z",
        "source_key": "source:key:z",
        "type": "greenhouse",
        "revision": 1,
    }
    second = {
        "source_id": "source-a",
        "source_key": "source:key:a",
        "type": "greenhouse",
        "revision": 1,
    }
    current = replace(
        candidate(1),
        run_snapshot_json=[first, second],
        run_snapshot_hash=acquisition_snapshot_hash([first, second]),
        source_snapshot_json=first,
        operation_source_id="source-z",
    )

    result = select_candidates((current,))

    assert result.eligible_count == 1
    assert result.rejection_counts == {}


def test_profile_baseline_id_matches_runtime_profile() -> None:
    assert BASELINE_PROFILE_ID == "e4aec18c-90fa-4553-ae3e-9e4655223683"


def test_store_is_exactly_fifty_tamper_evident_and_atomic(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "private")
    lines = tuple(f'{{"ordinal":{index}}}\n'.encode() for index in range(50))
    target = store.publish(
        dataset_id="a" * 64,
        dataset_lines=lines,
        provenance_lines=lines,
        label_lines=lines,
        internal={"count": 50},
    )
    assert store.verify(target.name)
    (target / "dataset.jsonl").write_bytes(b"tampered\n")
    assert not store.verify(target.name)
    with pytest.raises(ValueError, match="exactly_50"):
        store.publish(
            dataset_id="b" * 64,
            dataset_lines=lines[:1],
            provenance_lines=lines,
            label_lines=lines,
            internal={},
        )


def test_runtime_acknowledgement_and_materialization_are_offline(tmp_path: Path) -> None:
    values = tuple(candidate(index) for index in range(50))
    current = snapshot(values)
    runtime = CohortFreezeRuntime(
        SimpleNamespace(load=lambda: current),
        SnapshotStore(tmp_path / "bundle"),
        deployment=DeploymentIdentity("clean-commit", True, ALEMBIC_HEAD),
    )
    preview = runtime.preview()
    assert "Title 1" not in str(preview.payload)
    bundle = runtime.freeze(acknowledgement(preview.preview_sha256 or ""))
    assert runtime.verify(bundle.dataset_id)["status"] == "frozen"
    assert materialize(current, preview.selection)[4] == bundle.dataset_id


def test_cli_shape_rejects_generic_confirmation() -> None:
    args = _parser().parse_args(("evaluation", "f10-1c", "freeze", "--acknowledgement", "x"))
    assert args.f10_1c_command == "freeze"
    with pytest.raises(SystemExit):
        _parser().parse_args(("evaluation", "f10-1c", "freeze", "--yes"))


def test_repository_ignores_existing_downstream_tables(tmp_path: Path) -> None:
    database = tmp_path / "role-radar.db"
    source = {
        "source_id": "source-1",
        "source_key": "greenhouse:caylent",
        "type": "greenhouse",
        "revision": 1,
    }
    source_json = json.dumps([source], separators=(",", ":"))
    source_hash = canonical_hash([source])
    identity_value = "greenhouse:external:1"
    identity_digest = hashlib.sha256(identity_value.encode()).hexdigest()
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE continuous_acquisition_runs (
                id TEXT PRIMARY KEY, slot_key TEXT, state TEXT, snapshot_hash TEXT,
                snapshot_json TEXT, policy_version TEXT, started_at TEXT,
                finished_at TEXT, created_count INTEGER, observed_count INTEGER
            );
            CREATE TABLE continuous_acquisition_source_operations (
                id TEXT PRIMARY KEY, run_id TEXT, source_id TEXT,
                source_snapshot_json TEXT, intent_state TEXT, result_state TEXT,
                observed_count INTEGER, created_count INTEGER, started_at TEXT,
                finished_at TEXT
            );
            CREATE TABLE continuous_acquisition_run_jobs (
                id TEXT PRIMARY KEY, run_id TEXT, operation_id TEXT, job_id TEXT,
                disposition TEXT, provider_recency_at TEXT, recency_semantic TEXT,
                freshness_policy_version TEXT, identity_policy_version TEXT,
                provenance_hash TEXT, created_at TEXT
            );
            CREATE TABLE jobs (
                id TEXT PRIMARY KEY, title TEXT, company TEXT, location TEXT,
                description TEXT, application_url TEXT
            );
            CREATE TABLE job_identity_keys (
                id TEXT PRIMARY KEY, job_id TEXT, identity_kind TEXT,
                identity_version TEXT, identity_value TEXT, value_digest TEXT
            );
            CREATE TABLE candidate_profiles (
                id TEXT PRIMARY KEY, name TEXT, version INTEGER,
                schema_version INTEGER, profile_json TEXT, is_active INTEGER
            );
            CREATE TABLE alembic_version (version_num TEXT);
            CREATE TABLE job_source_references (id TEXT);
            CREATE TABLE job_extractions (id TEXT);
            CREATE TABLE job_scores (id TEXT);
            CREATE TABLE job_deep_evaluations (id TEXT);
            """
        )
        connection.execute(
            "INSERT INTO continuous_acquisition_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                BOUNDARY_RUN_ID,
                "continuous-acquisition:daily-slot-v1:2026-08-01",
                "completed",
                source_hash,
                source_json,
                "continuous-acquisition-v1",
                "2026-08-01T00:00:00Z",
                "2026-08-01T00:01:00Z",
                1,
                1,
            ),
        )
        connection.execute(
            "INSERT INTO continuous_acquisition_source_operations "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "operation-1",
                BOUNDARY_RUN_ID,
                "source-1",
                json.dumps(source, separators=(",", ":")),
                "succeeded",
                "succeeded",
                1,
                1,
                "2026-08-01T00:00:00Z",
                "2026-08-01T00:01:00Z",
            ),
        )
        connection.execute(
            "INSERT INTO continuous_acquisition_run_jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "link-1",
                BOUNDARY_RUN_ID,
                "operation-1",
                "job-1",
                "created",
                "2026-07-25T00:00:00Z",
                "provider_updated_at_proxy",
                "freshness-v1",
                "strong-identity-v1",
                "a" * 64,
                "2026-08-01T00:00:30Z",
            ),
        )
        connection.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?)",
            ("job-1", "Senior Frontend Engineer", "Company", "Remote", "Description", None),
        )
        connection.execute(
            "INSERT INTO job_identity_keys VALUES (?, ?, ?, ?, ?, ?)",
            (
                "identity-1",
                "job-1",
                "source_external_id",
                "strong-identity-v1",
                identity_value,
                identity_digest,
            ),
        )
        connection.execute(
            "INSERT INTO candidate_profiles VALUES (?, ?, ?, ?, ?, ?)",
            (
                BASELINE_PROFILE_ID,
                "Perfil Semilla",
                BASELINE_PROFILE_VERSION,
                BASELINE_PROFILE_SCHEMA,
                "{}",
                1,
            ),
        )
        connection.execute("INSERT INTO alembic_version VALUES (?)", (ALEMBIC_HEAD,))
        connection.commit()
    finally:
        connection.close()

    snapshot = SQLiteSnapshotRepository(database).load()

    assert len(snapshot.candidates) == 1
    assert snapshot.candidates[0].job_id == "job-1"
