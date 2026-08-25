"""Offline Gate E/F and F10.1F freeze transaction coverage."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from role_radar.evaluation.fresh_acquisition import gate_e
from role_radar.evaluation.fresh_acquisition.freeze import (
    DIRNAME_OPERATOR,
    DIRNAME_PILOT,
    DIRNAME_PRIVATE,
    DIRNAME_SEALED_HOLDOUT,
    FreezeBindings,
    run_freeze_transaction,
    verify_frozen_publication,
)
from role_radar.evaluation.fresh_acquisition.gate_e import run_gate_e_preview
from role_radar.evaluation.fresh_acquisition.gate_f import (
    GateFError,
    run_gate_f_materialization,
)
from role_radar.evaluation.fresh_acquisition.provenance import LIVE_NAMESPACE
from role_radar.evaluation.profile_relevance.contracts import (
    CanonicalPayload,
    ProfileRelevanceInput,
)
from tests.unit.test_fresh_acquisition_provenance_store_report import _provenance
from tests.unit.test_profile_relevance_materialization import (
    _build_approved_and_context,
    _build_input,
)


def _live_namespace_input() -> ProfileRelevanceInput:
    base = _build_input()
    return replace(base, sealed_snapshot=replace(base.sealed_snapshot, namespace=LIVE_NAMESPACE))


def test_gate_e_runs_only_sanitized_preview_with_no_materialization_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _live_namespace_input()
    provenance = _provenance()

    # The offline DTO fixture uses synthetic 32-byte seeds. Gate E's separate
    # test below asserts the live constants; this patch keeps this test focused
    # on the Gate E boundary and its no-materialization behavior.
    monkeypatch.setattr(gate_e, "LIVE_SELECTION_SEED", inputs.sampling_policy.selection_seed)
    monkeypatch.setattr(gate_e, "LIVE_PARTITION_SEED", inputs.partition_policy.partition_seed)

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
        )
    assert mismatch.value.code == "gate_f_cross_gate_substitution"


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
    )
    provenance = _provenance()

    operator = _payload_object(payloads.operator_payloads, "operator_preview")
    population = _payload_object(payloads.private_payloads, "population")
    pilot = _payload_object(payloads.pilot_payloads, "pilot_binding")
    holdout = _payload_object(payloads.holdout_payloads, "holdout_binding")
    root = tmp_path / "f10-1f"
    bindings = FreezeBindings(
        dataset_id=str(operator["dataset_id"]),
        pool_sha256="1" * 64,
        provenance_sha256=provenance.provenance_sha256,
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
        namespace=LIVE_NAMESPACE,
        root=str(root),
    )

    benchmark = run_freeze_transaction(
        root=root,
        bindings=bindings,
        payloads=payloads,
        provenance=provenance,
    )
    assert benchmark.verified
    assert benchmark.receipt.transaction_complete
    assert set(benchmark.capability_kinds) == {"private", "pilot", "sealed_holdout"}
    assert verify_frozen_publication(root=root, benchmark=benchmark, payloads=payloads)

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
        payloads=payloads,
        provenance=provenance,
    )
    assert rerun.receipt.canonical_bytes == benchmark.receipt.canonical_bytes
    assert verify_frozen_publication(root=root, benchmark=rerun, payloads=payloads)
