"""Offline Gate E/F and F10.1F freeze transaction coverage."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from role_radar.evaluation.profile_relevance.contracts import (
    CanonicalPayload,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    build_f_handoff,
    synthetic_test_adapter,
)
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import (
    DIRNAME_OPERATOR,
    DIRNAME_PILOT,
    DIRNAME_PRIVATE,
    DIRNAME_SEALED_HOLDOUT,
    FreezeBindings,
    FreezeError,
    run_freeze_transaction,
    verify_frozen_publication,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import run_gate_e_preview
from role_radar.evaluation.profile_relevant_acquisition.gate_f_materialization import (
    GateFError,
    run_gate_f_materialization,
)
from tests.unit.test_profile_relevance_materialization import (
    _build_approved_and_context,
    _build_input,
)
from tests.unit.test_profile_relevant_acquisition_provenance_store_report import _provenance


def _live_namespace_input() -> ProfileRelevanceInput:
    base = _build_input()
    return replace(
        base, sealed_snapshot=replace(base.sealed_snapshot, namespace="synthetic-f10-1f")
    )


def test_gate_e_runs_only_sanitized_preview_with_no_materialization_bytes() -> None:
    inputs = _live_namespace_input()
    provenance = _provenance()

    result, record = run_gate_e_preview(inputs=inputs, provenance=provenance)

    assert result.sanitized_preview.canonical_payload.endswith(b"\n")
    assert b"title" not in result.sanitized_preview.canonical_payload
    assert b"description" not in result.sanitized_preview.canonical_payload
    assert record.provenance_sha256 == provenance.provenance_sha256
    assert b"holdout_membership_sha256" in record.canonical_bytes


def test_gate_f_materializes_only_exact_approved_context_bindings() -> None:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)

    payloads = run_gate_f_materialization(
        approved_preview=approved,
        materialization_context=context,
        test_only_adapter=synthetic_test_adapter(),
    )
    assert len(payloads.private_payloads) == 6
    assert len(payloads.operator_payloads) == 1
    assert len(payloads.pilot_payloads) == 2
    assert {item.logical_name for item in payloads.holdout_payloads} == {
        "holdout_binding",
        "holdout_sealed_view",
    }

    with pytest.raises(GateFError) as mismatch:
        run_gate_f_materialization(
            approved_preview=approved,
            materialization_context=replace(
                context,
                operation_binding_sha256="f" * 64,
            ),
            test_only_adapter=synthetic_test_adapter(),
        )
    assert mismatch.value.code == "gate_f_cross_gate_substitution"


def test_gate_f_legacy_materializer_requires_explicit_test_boundary() -> None:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)
    with pytest.raises(GateFError) as blocked:
        run_gate_f_materialization(
            approved_preview=approved,
            materialization_context=context,
        )
    assert blocked.value.code == "gate_f_execution_authorization_required"


def _payload_object(group: tuple[CanonicalPayload, ...], name: str) -> dict[str, object]:
    payload = next(item for item in group if item.logical_name == name)
    return cast(dict[str, object], json.loads(payload.canonical_bytes.rstrip(b"\n")))


def _int_field(value: dict[str, object], key: str) -> int:
    field = value[key]
    assert isinstance(field, int)
    return field


def test_freeze_publishes_manifest_capabilities_and_receipt_once(tmp_path: Path) -> None:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)
    payloads = run_gate_f_materialization(
        approved_preview=approved,
        materialization_context=context,
        test_only_adapter=synthetic_test_adapter(),
    )
    root = tmp_path / "f10-1f"
    provenance = _provenance(root=str(root))

    operator = _payload_object(payloads.operator_payloads, "operator_preview")
    population = _payload_object(payloads.private_payloads, "population")
    pilot = _payload_object(payloads.pilot_payloads, "pilot_binding")
    holdout = _payload_object(payloads.holdout_payloads, "holdout_binding")
    bindings = FreezeBindings(
        dataset_id=str(operator["dataset_id"]),
        pool_sha256="1" * 64,
        provenance_sha256=provenance.provenance_sha256,
        f_challenge_sha256="a" * 64,
        inventory_sha256=provenance.inventory_sha256,
        source_plan_sha256=inputs.sealed_snapshot.source_plan_sha256,
        preview_input_sha256=str(operator["preview_input_sha256"]),
        selection_sha256=str(operator["selection_sha256"]),
        partition_sha256=approved.partition_sha256,
        pilot_membership_sha256=str(pilot["pilot_membership_sha256"]),
        holdout_membership_sha256=str(holdout["holdout_membership_sha256"]),
        observation_count=_int_field(population, "observation_count"),
        corpus_count=_int_field(operator, "corpus_count"),
        pilot_count=_int_field(operator, "pilot_count"),
        holdout_count=_int_field(operator, "holdout_count"),
        per_board_cap=4,
        per_company_cap=2,
        namespace="synthetic-f10-1f",
        root=str(root),
    )

    f_handoff = build_f_handoff(
        operation_id="freeze-op",
        challenge_sha256="a" * 64,
        provenance_sha256=provenance.provenance_sha256,
        artifact_class=ArtifactClass.SYNTHETIC,
        payloads=payloads,
    )
    benchmark = run_freeze_transaction(
        root=root,
        bindings=bindings,
        f_handoff=f_handoff,
        provenance=provenance,
        test_only_adapter=synthetic_test_adapter(),
    )
    assert benchmark.verified
    assert benchmark.receipt.transaction_complete
    assert set(benchmark.capability_kinds) == {"private", "pilot", "sealed_holdout"}
    assert verify_frozen_publication(
        root=root,
        benchmark=benchmark,
        payloads=payloads,
        test_only_adapter=synthetic_test_adapter(),
    )

    dataset = root / benchmark.dataset_id
    assert (dataset / "manifest.json").is_file()
    assert (dataset / "sealed_pool_manifest.json").is_file()
    assert (dataset / "checksums.sha256").is_file()
    assert (dataset / "receipt.json").is_file()
    assert {item.name for item in (dataset / "capabilities").iterdir()} == {
        "private.json",
        "pilot.json",
        "sealed_holdout.json",
    }
    assert {item.name for item in (dataset / DIRNAME_PRIVATE).iterdir()} == {
        "gate_decisions.json",
        "population.json",
        "preview.json",
        "provenance.json",
        "sampling_cells.json",
        "selection.json",
    }
    assert (dataset / DIRNAME_OPERATOR / "operator_preview.json").is_file()
    assert (dataset / DIRNAME_PILOT / "pilot_binding.json").is_file()
    assert (dataset / DIRNAME_SEALED_HOLDOUT / "holdout_binding.json").is_file()

    receipt = json.loads((dataset / "receipt.json").read_bytes())
    assert receipt["transaction_complete"] is True
    assert not any(key in receipt for key in ("title", "company", "description", "url", "source"))
    assert not (tmp_path / "snapshot").exists()
    assert not (tmp_path / "f10.1").exists()
    assert not (tmp_path / "holdout").exists()

    rerun = run_freeze_transaction(
        root=root,
        bindings=bindings,
        f_handoff=f_handoff,
        provenance=provenance,
        test_only_adapter=synthetic_test_adapter(),
    )
    assert rerun.receipt.canonical_bytes == benchmark.receipt.canonical_bytes
    assert verify_frozen_publication(
        root=root,
        benchmark=rerun,
        payloads=payloads,
        test_only_adapter=synthetic_test_adapter(),
    )


def test_freeze_legacy_publication_requires_explicit_boundary(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as blocked:
        run_freeze_transaction(
            root=tmp_path / "f10-1f",
            bindings=object(),  # type: ignore[arg-type]
            payloads=object(),  # type: ignore[arg-type]
            provenance=object(),  # type: ignore[arg-type]
        )
    assert getattr(blocked.value, "code", "") == "freeze_execution_authorization_required"


def test_freeze_rejects_materialized_payloads_without_f_handoff(tmp_path: Path) -> None:
    with pytest.raises(FreezeError) as blocked:
        run_freeze_transaction(
            root=tmp_path / "f10-1f",
            bindings=object(),  # type: ignore[arg-type]
            payloads=object(),  # type: ignore[arg-type]
            provenance=object(),  # type: ignore[arg-type]
            test_only_adapter=synthetic_test_adapter(),
        )
    assert blocked.value.code == "freeze_f_handoff_required"
