"""Focused, offline guardrails for the Gate E preview boundary."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevance.policy import MAX_CORPUS_CARDINALITY
from role_radar.evaluation.profile_relevant_acquisition import gate_e_preview
from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    GateEAuthorizationError,
    GateEAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import (
    GateEError,
    GateEPreviewRecord,
    run_gate_e_preview,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_service import (
    GateEPublicResult,
    run_gate_e_offline_preview,
)
from tests.unit.test_profile_relevance_materialization import _build_input
from tests.unit.test_profile_relevant_acquisition_provenance_store_report import _provenance
from tests.unit.test_profile_relevant_gate_d_bounded_acquisition import _request


def _open_snapshot():
    snapshot = _build_input().sealed_snapshot
    object.__setattr__(snapshot, "state", "open")
    return snapshot


def _valid_pair():
    inputs = replace(
        _build_input(),
        sealed_snapshot=replace(_build_input().sealed_snapshot, namespace="synthetic-f10-1f"),
    )
    provenance = _provenance(
        relevance_policy_sha256=inputs.relevance_policy.policy_sha256,
        selection_seed=inputs.sampling_policy.selection_seed,
        partition_seed=inputs.partition_policy.partition_seed,
    )
    return inputs, provenance


def test_valid_synthetic_preview_is_pure_deterministic_and_authenticated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, provenance = _valid_pair()
    calls = 0
    original = gate_e_preview.compute_preview

    def counted(value):
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(gate_e_preview, "compute_preview", counted)
    first = run_gate_e_preview(inputs=inputs, provenance=provenance)
    second = run_gate_e_preview(inputs=inputs, provenance=provenance)

    assert calls == 2
    assert (
        first[0].sanitized_preview.canonical_payload
        == second[0].sanitized_preview.canonical_payload
    )
    assert first[1] == second[1]
    assert isinstance(first[1], GateEPreviewRecord)
    assert first[1].provenance_sha256 == provenance.provenance_sha256
    assert set(json.loads(first[0].sanitized_preview.canonical_payload)) == {
        "corpus_count",
        "holdout_count",
        "holdout_membership_sha256",
        "partition_sha256",
        "pilot_count",
        "pilot_membership_sha256",
        "preview_input_sha256",
        "schema_version",
        "selection_sha256",
        "total_count",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sealed_snapshot", _open_snapshot()),
        ("relevance_policy", replace(_build_input().relevance_policy, policy_sha256="0" * 64)),
        ("sampling_policy", replace(_build_input().sampling_policy, selection_seed="0" * 64)),
        ("partition_policy", replace(_build_input().partition_policy, partition_seed="0" * 64)),
        ("preview_input_sha256", "0" * 64),
    ),
)
def test_invalid_snapshot_seed_policy_or_binding_blocks_before_preview(
    field: str,
    value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs, provenance = _valid_pair()
    calls = 0

    def must_not_preview(_value):
        nonlocal calls
        calls += 1
        raise AssertionError("preview reached before Gate E validation")

    monkeypatch.setattr(gate_e_preview, "compute_preview", must_not_preview)
    with pytest.raises((GateEError, ValueError)):
        run_gate_e_preview(inputs=replace(inputs, **{field: value}), provenance=provenance)
    assert calls == 0


def test_cardinality_limit_blocks_before_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    inputs, provenance = _valid_pair()
    oversized = replace(
        inputs.sampling_policy,
        corpus_cardinality=MAX_CORPUS_CARDINALITY + 1,
    )
    monkeypatch.setattr(gate_e_preview, "compute_preview", lambda _value: pytest.fail("called"))
    with pytest.raises(GateEError) as blocked:
        run_gate_e_preview(inputs=replace(inputs, sampling_policy=oversized), provenance=provenance)
    assert blocked.value.code == "input_limit_exceeded"


def test_public_gate_e_dto_is_an_explicit_allowlist() -> None:
    fields = {
        "operation_id": "op",
        "preregistration_sha256": "a" * 64,
        "source_plan_sha256": "b" * 64,
        "preview_input_sha256": "c" * 64,
        "selection_sha256": None,
        "partition_sha256": None,
        "pilot_membership_sha256": None,
        "holdout_membership_sha256": None,
        "sanitized_preview_sha256": None,
        "provenance_sha256": "d" * 64,
        "corpus_count": 0,
        "pilot_count": 0,
        "holdout_count": 0,
        "feasibility": "infeasible",
        "status": "blocked",
        "code": "blocked",
    }
    assert set(GateEPublicResult(**fields).as_dict()) == set(fields)


def test_cli_preview_keeps_generic_pre_runtime_block(capsys) -> None:
    assert evaluation_f10_1f.run(type("Args", (), {"f10_1f_command": "preview"})()) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["code"] == "BLOCK-0"
    assert payload["live_execution"] == "disabled"


def test_gate_d_expiry_is_rechecked_before_gate_e_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate_d_request = _request(tmp_path)
    authorization = GateEAuthorizationRequest(
        operation_id=gate_d_request.operation_id,
        lineage_id=gate_d_request.lineage_id,
        gate_d_request=gate_d_request,
        gate_d_result=cast(Any, object()),
        parent_pool_manifest=cast(Any, object()),
        post_c_request=gate_d_request.post_c_request,
        post_c_seal=gate_d_request.post_c_seal,
        provenance=cast(Any, object()),
        current_commit_sha256=gate_d_request.current_commit_sha256,
        profile_relevance_input=object(),
    )
    monkeypatch.setattr(
        "role_radar.evaluation.profile_relevant_acquisition.gate_e_service.adapt_gate_e_input",
        lambda _authorized: pytest.fail("Gate E adapter reached after Gate D expiry"),
    )

    with pytest.raises(GateEAuthorizationError) as blocked:
        run_gate_e_offline_preview(
            authorization=authorization,
            clock=lambda: datetime(2099, 1, 1, tzinfo=UTC),
        )
    assert blocked.value.code == "authorization_expired"
