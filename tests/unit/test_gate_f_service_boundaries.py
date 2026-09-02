"""Service-level Gate F effect-boundary and sanitization contracts."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevant_acquisition import gate_f_service
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import FreezeError
from tests.unit.test_profile_relevance_materialization import (
    _build_approved_and_context,
    _build_input,
)

NOW = datetime(2026, 8, 25, 2, 30, tzinfo=UTC)


def _request(tmp_path: Path) -> tuple[Any, Any, Any, Any]:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)
    result = __import__(
        "role_radar.evaluation.profile_relevance", fromlist=["compute_preview"]
    ).compute_preview(inputs)
    root = tmp_path / "isolated-f10-1f"
    provenance = SimpleNamespace(
        namespace="synthetic-f10-1f", root=str(root), provenance_sha256="b" * 64
    )
    authorization = SimpleNamespace(
        operation_id="operation-f", challenge_sha256="a" * 64, test_only_adapter=object()
    )
    request = SimpleNamespace(
        authorization=authorization,
        provenance=provenance,
        dataset_id="d" * 64,
        destination_root=root,
        gate_e_result=result,
        materialization_context=context,
        profile_relevance_input=inputs,
    )
    return request, approved, context, inputs


def _benchmark(request: Any) -> Any:
    receipt = SimpleNamespace(
        receipt_sha256="4" * 64,
        private_artifact_count=6,
        pilot_artifact_count=2,
        holdout_artifact_count=2,
    )
    return SimpleNamespace(
        dataset_id=request.dataset_id,
        namespace=request.provenance.namespace,
        dataset_manifest=SimpleNamespace(manifest_sha256="5" * 64),
        receipt=receipt,
        capability_kinds=("private", "pilot", "sealed_holdout"),
    )


def _wire_service(
    monkeypatch: pytest.MonkeyPatch, request: Any, context: Any, payloads: Any
) -> tuple[dict[str, int], Any, Any, object]:
    calls = {"authorize": 0, "materialize": 0, "freeze": 0}
    bindings = object()

    def authorize(_request: Any, *, now: datetime | None = None) -> Any:
        calls["authorize"] += 1
        return SimpleNamespace(request=request)

    def materialize(**kwargs: Any) -> Any:
        calls["materialize"] += 1
        assert kwargs["materialization_context"] is context
        return payloads

    def freeze(**kwargs: Any) -> Any:
        calls["freeze"] += 1
        assert kwargs["root"] == request.destination_root
        return _benchmark(request)

    monkeypatch.setattr(gate_f_service, "authorize_gate_f", authorize)
    monkeypatch.setattr(gate_f_service, "freeze_bindings_for_request", lambda _request: bindings)
    monkeypatch.setattr(
        gate_f_service,
        "adapt_gate_f_input",
        lambda _authorized: (request.profile_relevance_input, context),
    )
    return calls, materialize, freeze, bindings


def test_valid_exact_synthetic_operation_materializes_and_freezes_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, approved, context, _inputs = _request(tmp_path)
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    payloads = materialize_payload_bytes(approved, context)
    calls, materialize, freeze, bindings = _wire_service(monkeypatch, request, context, payloads)
    result = gate_f_service.run_gate_f_materialization_freeze(
        request=request,
        freeze_bindings=bindings,
        clock=lambda: NOW,
        materializer=materialize,
        freezer=freeze,
    )
    assert calls["materialize"] == calls["freeze"] == 1
    assert result.public.as_dict() == {
        "dataset_id": "d" * 64,
        "namespace": "synthetic-f10-1f",
        "preview_input_sha256": request.profile_relevance_input.preview_input_sha256,
        "manifest_sha256": "5" * 64,
        "receipt_sha256": "4" * 64,
        "private_artifact_count": 6,
        "pilot_artifact_count": 2,
        "holdout_artifact_count": 2,
        "capability_kinds": ("private", "pilot", "sealed_holdout"),
        "status": "completed",
        "code": "gate_f_materialization_freeze_completed",
    }
    assert not {"root", "path", "payload", "items", "labels", "history"} & set(
        result.public.as_dict()
    )


@pytest.mark.parametrize(
    "code",
    ("gate_f_authorization_invalid", "authorization_expired", "gate_f_operation_lineage_mismatch"),
)
def test_invalid_authorization_blocks_before_all_effects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: str
) -> None:
    request, _approved, context, _inputs = _request(tmp_path)
    calls, materialize, freeze, _bindings = _wire_service(monkeypatch, request, context, object())

    def blocked(_request: Any, *, now: datetime | None = None) -> Any:
        raise FreezeError(code)

    monkeypatch.setattr(gate_f_service, "authorize_gate_f", blocked)
    with pytest.raises(FreezeError) as error:
        gate_f_service.run_gate_f_materialization_freeze(
            request=request,
            freeze_bindings=_bindings,
            clock=lambda: NOW,
            materializer=materialize,
            freezer=freeze,
        )
    assert error.value.code == code
    assert calls["materialize"] == calls["freeze"] == 0
    assert not request.destination_root.exists()


def test_final_pre_freeze_expiry_check_blocks_freeze(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, approved, context, _inputs = _request(tmp_path)
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    payloads = materialize_payload_bytes(approved, context)
    calls, materialize, freeze, bindings = _wire_service(monkeypatch, request, context, payloads)
    checks = iter((NOW, NOW, NOW))

    def authorize(_request: Any, *, now: datetime | None = None) -> Any:
        value = next(checks)
        if value == NOW and calls["materialize"] == 1:
            raise FreezeError("authorization_expired")
        return SimpleNamespace(request=request)

    monkeypatch.setattr(gate_f_service, "authorize_gate_f", authorize)
    with pytest.raises(FreezeError, match="authorization_expired"):
        gate_f_service.run_gate_f_materialization_freeze(
            request=request,
            freeze_bindings=bindings,
            clock=lambda: NOW,
            materializer=materialize,
            freezer=freeze,
        )
    assert calls["materialize"] == 1
    assert calls["freeze"] == 0


def test_freeze_binding_mismatch_blocks_before_adapter_or_filesystem_effects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, _approved, context, _inputs = _request(tmp_path)
    calls, materialize, freeze, _bindings = _wire_service(monkeypatch, request, context, object())
    with pytest.raises(FreezeError, match="freeze_bindings_mismatch"):
        gate_f_service.run_gate_f_materialization_freeze(
            request=request,
            freeze_bindings=object(),
            clock=lambda: NOW,
            materializer=materialize,
            freezer=freeze,
        )
    assert calls["materialize"] == calls["freeze"] == 0
    assert not request.destination_root.exists()


@pytest.mark.parametrize("state", ("incomplete", "replaced", "conflicting"))
def test_existing_destination_states_have_zero_effect_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: str
) -> None:
    request, _approved, context, _inputs = _request(tmp_path)
    target = request.destination_root / request.dataset_id
    request.destination_root.mkdir()
    if state == "replaced":
        target.write_text("replacement")
    else:
        target.mkdir()
        if state == "conflicting":
            (target / "manifest.json").write_text("{}")
    calls, materialize, freeze, bindings = _wire_service(monkeypatch, request, context, object())
    expected_code = "freeze_replay_conflict" if state == "replaced" else "freeze_replay_incomplete"
    with pytest.raises(FreezeError, match=expected_code):
        gate_f_service.run_gate_f_materialization_freeze(
            request=request,
            freeze_bindings=bindings,
            clock=lambda: NOW,
            materializer=materialize,
            freezer=freeze,
        )
    assert calls["materialize"] == calls["freeze"] == 0


def test_exact_replay_reuses_publication_without_materializing_or_freezing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, _approved, context, _inputs = _request(tmp_path)
    replay = SimpleNamespace(status="completed", code="gate_f_materialization_freeze_replayed")
    calls, materialize, freeze, bindings = _wire_service(monkeypatch, request, context, object())
    monkeypatch.setattr(gate_f_service, "_replay_preflight", lambda _request: replay)
    result = gate_f_service.run_gate_f_materialization_freeze(
        request=request,
        freeze_bindings=bindings,
        clock=lambda: NOW,
        materializer=materialize,
        freezer=freeze,
    )
    assert result.public is replay
    assert calls["materialize"] == calls["freeze"] == 0


def test_service_does_not_rerun_selection_or_partition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, approved, context, _inputs = _request(tmp_path)
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    payloads = materialize_payload_bytes(approved, context)
    calls, materialize, freeze, bindings = _wire_service(monkeypatch, request, context, payloads)
    monkeypatch.setattr(
        "role_radar.evaluation.profile_relevance.compute_preview",
        lambda _inputs: pytest.fail("selection/partition rerun"),
    )
    gate_f_service.run_gate_f_materialization_freeze(
        request=request,
        freeze_bindings=bindings,
        clock=lambda: NOW,
        materializer=materialize,
        freezer=freeze,
    )
    assert calls["materialize"] == calls["freeze"] == 1


def test_gate_f_service_and_cli_remain_architecturally_bounded() -> None:
    source = Path(
        "src/role_radar/evaluation/profile_relevant_acquisition/gate_f_service.py"
    ).read_text()
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id in {"run_gate_f_materialization", "run_freeze_transaction"}
    ]
    assert {node.id for node in calls} == {"run_gate_f_materialization", "run_freeze_transaction"}
    assert "run_authoritative_f10_1f" not in source
    assert "role_radar.repositories" not in source
    assert "role_radar.db" not in source
    assert evaluation_f10_1f.run(SimpleNamespace(f10_1f_command="freeze")) == 2
