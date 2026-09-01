"""Offline contracts for provenance, private publication, and Gate C reports."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from role_radar.discovery.planner_v2 import plan_profile_discovery
from role_radar.evaluation.profile_relevant_acquisition.capability_seal import (
    build_capability_seal,
)
from role_radar.evaluation.profile_relevant_acquisition.discovery_runtime import (
    ReportOnlyError,
    ReportOnlyRuntimeConfig,
    persist_private_evidence,
    run_report_only_discovery,
)
from role_radar.evaluation.profile_relevant_acquisition.provenance import (
    ALEMBIC_HEAD_F10_1B,
    ProvenanceBundle,
    ProvenanceError,
    build_provenance_bundle,
    validate_provenance,
)
from role_radar.evaluation.profile_relevant_acquisition.store import (
    ProfileRelevantAcquisitionStore,
    StoreError,
)
from tests.unit.test_discovery_planner_v2 import policy, terms


def _provenance(*, root: str = "/tmp/role-radar-f10-1f-test") -> ProvenanceBundle:
    values = {
        "diff_sha256": "d" * 64,
        "status_sha256": "e" * 64,
        "lock_sha256": "f" * 64,
        "profile_binding_sha256": "1" * 64,
        "discovery_policy_sha256": "2" * 64,
        "relevance_policy_sha256": "3" * 64,
        "display_contract_sha256": "4" * 64,
        "planner_sha256": "5" * 64,
        "query_plan_sha256": "6" * 64,
        "sampling_formula_sha256": "7" * 64,
        "partition_formula_sha256": "8" * 64,
        "inventory_sha256": "9" * 64,
    }
    return build_provenance_bundle(
        commit_sha="a" * 40,
        alembic_head=ALEMBIC_HEAD_F10_1B,
        window_start_utc="2026-08-25T00:00:00Z",
        window_end_utc="2026-08-25T01:00:00Z",
        cutoff_utc="2026-08-25T00:30:00Z",
        old_artifact_hashes={"lock": "0" * 64},
        selection_seed="a" * 64,
        partition_seed="b" * 64,
        per_board_cap=4,
        per_company_cap=2,
        corpus_total=4,
        pilot_count=2,
        holdout_count=2,
        namespace="synthetic-f10-1f",
        root=root,
        **values,
    )


def test_provenance_requires_explicit_design_and_null_pre_gate_c_source_plan() -> None:
    bundle = _provenance()

    assert (bundle.corpus_total, bundle.pilot_count, bundle.holdout_count) == (4, 2, 2)
    assert (bundle.per_board_cap, bundle.per_company_cap) == (4, 2)
    assert bundle.namespace == "synthetic-f10-1f"
    assert bundle.source_plan_hash is None
    assert json.loads(bundle.canonical_bytes)["source_plan_hash"] is None
    validate_provenance(bundle)

    with pytest.raises(ProvenanceError) as tampered:
        validate_provenance(replace(bundle, canonical_bytes=b"{}"))
    assert tampered.value.code == "provenance_hash_mismatch"


def test_provenance_rejects_non_live_seed_and_non_null_source_plan() -> None:
    with pytest.raises(ProvenanceError) as selection:
        _provenance_with(selection_seed="0" * 63)
    assert selection.value.code == "provenance_selection_seed_invalid"

    bundle = _provenance()
    with pytest.raises(ProvenanceError) as source_plan:
        replace(bundle, source_plan_hash="a" * 64)
    assert source_plan.value.code == "provenance_source_plan_must_be_null_pre_gate_c"


def _provenance_with(**overrides: str) -> ProvenanceBundle:
    kwargs = {
        "selection_seed": "a" * 64,
        "partition_seed": "b" * 64,
    }
    kwargs.update(overrides)
    values = {
        "diff_sha256": "d" * 64,
        "status_sha256": "e" * 64,
        "lock_sha256": "f" * 64,
        "profile_binding_sha256": "1" * 64,
        "discovery_policy_sha256": "2" * 64,
        "relevance_policy_sha256": "3" * 64,
        "display_contract_sha256": "4" * 64,
        "planner_sha256": "5" * 64,
        "query_plan_sha256": "6" * 64,
        "sampling_formula_sha256": "7" * 64,
        "partition_formula_sha256": "8" * 64,
        "inventory_sha256": "9" * 64,
    }
    return build_provenance_bundle(
        commit_sha="a" * 40,
        alembic_head=ALEMBIC_HEAD_F10_1B,
        window_start_utc="2026-08-25T00:00:00Z",
        window_end_utc="2026-08-25T01:00:00Z",
        cutoff_utc="2026-08-25T00:30:00Z",
        old_artifact_hashes={"lock": "0" * 64},
        per_board_cap=4,
        per_company_cap=2,
        corpus_total=4,
        pilot_count=2,
        holdout_count=2,
        namespace="synthetic-f10-1f",
        root="/tmp/role-radar-f10-1f-test",
        **values,
        **kwargs,
    )


def test_private_store_is_namespace_bound_and_idempotent(tmp_path: Path) -> None:
    store = ProfileRelevantAcquisitionStore(tmp_path / "f10-1f", "synthetic-f10-1f")
    dataset_id = "a" * 64
    pool = (b'{"external_id":"1"}\n',)
    manifest = {"schema": "sealed-pool", "count": 1}

    target = store.publish_sealed_pool(dataset_id=dataset_id, pool_lines=pool, manifest=manifest)
    assert store.verify(dataset_id)
    assert (
        store.publish_sealed_pool(dataset_id=dataset_id, pool_lines=pool, manifest=manifest)
        == target
    )

    with pytest.raises(StoreError) as conflict:
        store.publish_sealed_pool(
            dataset_id=dataset_id,
            pool_lines=(b"different\n",),
            manifest=manifest,
        )
    assert conflict.value.code == "store_id_conflict"

    seal = build_capability_seal(
        dataset_id=dataset_id,
        namespace="synthetic-f10-1f",
        root=str(store.root),
        kind="private",
        payloads_sha256="b" * 64,
        artifact_count=1,
    )
    seal_object = json.loads(seal.canonical_bytes)
    cap = store.publish_capability_seal(dataset_id=dataset_id, seal=seal_object)
    assert store.publish_capability_seal(dataset_id=dataset_id, seal=seal_object) == cap
    with pytest.raises(StoreError) as cap_conflict:
        store.publish_capability_seal(dataset_id=dataset_id, seal={"changed": True})
    assert cap_conflict.value.code == "store_capability_conflict"

    with pytest.raises(StoreError) as namespace:
        ProfileRelevantAcquisitionStore(tmp_path / "other", namespace="NOT_VALID")
    assert namespace.value.code == "store_namespace_invalid"


def test_report_only_is_zero_mutation_and_sanitizes_evidence(tmp_path: Path) -> None:
    plan = plan_profile_discovery(terms(policy()), policy())
    same = {"Source": 1, "Job": 1, "registration": 0}
    transitions: list[tuple[dict[str, object], ...]] = []
    result = run_report_only_discovery(
        plan=plan,
        config=ReportOnlyRuntimeConfig(
            evidence_root=tmp_path / "evidence",
            before_after=lambda: (same, same.copy()),
            ledger_reconcile=transitions.append,
        ),
        expected_plan_sha256=plan.plan_sha256,
    )

    assert result.budget.consumed_brave == result.budget.consumed_tavily == 0
    assert result.ledger_transitions == ()
    assert transitions == [()]
    assert all(not hasattr(item, "canonical_query") for item in result.private_requests)
    assert all(
        item.destination_fingerprint and len(item.destination_fingerprint) == 16
        for item in result.private_requests
    )

    evidence = persist_private_evidence(result, tmp_path / "evidence")
    raw = evidence.read_bytes()
    assert plan.queries[0].canonical_query.encode() not in raw
    assert b"query_count" not in raw
    stored = json.loads(raw)
    assert set(stored) == {
        "budget",
        "plan_sha256",
        "private_evidence_sha256",
        "private_requests",
        "report_sha256",
    }


def test_report_only_rejects_product_mutation(tmp_path: Path) -> None:
    plan = plan_profile_discovery(terms(policy()), policy())
    with pytest.raises(ReportOnlyError) as exc:
        run_report_only_discovery(
            plan=plan,
            config=ReportOnlyRuntimeConfig(
                evidence_root=tmp_path / "evidence",
                before_after=lambda: ({"Job": 1}, {"Job": 2}),
            ),
        )
    assert exc.value.code == "report_only_product_mutation_detected"
