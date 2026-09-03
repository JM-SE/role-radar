"""Focused contract tests for the concrete, offline R2 adapter boundary.

These tests deliberately stop at the typed boundary.  They do not construct a
provider, database, filesystem root, or runtime artifact decoder.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import get_type_hints

import pytest

from role_radar.evaluation.r2_operational_artifacts import (
    ResolvedGateCInput,
    ResolvedGateDInput,
    ResolvedGateEInput,
    ResolvedGateFInput,
    ResolvedPostCInput,
)
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import make_test_capability
from role_radar.evaluation.r2_operational_service import (
    ConcreteGateCInvoker,
    ConcreteGateDInvoker,
    ConcreteGateEInvoker,
    ConcreteGateFInvoker,
    ConcretePostCInvoker,
    GateName,
    concrete_gate_invokers,
)


def _packet(gate: str = "c") -> OperationPacket:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return OperationPacket(
        "op-r2-test",
        gate,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "f" * 64,
        "r2-test-namespace",
        "/tmp/role-radar-r2-test",
        now,
        now + timedelta(hours=1),
        "1" * 64,
        "2" * 64,
        1,
        1,
        1,
        1,
        "r2-capability",
        "approval",
        "3" * 64,
        now + timedelta(hours=1),
        "nonce-r2-test",
        ("4" * 64,),
    )


class _NeverResolver:
    """A resolver sentinel: an invalid binding must not resolve an artifact."""

    def __init__(self) -> None:
        self.calls = 0

    def __getattr__(self, _name: str) -> object:
        self.calls += 1
        raise AssertionError("resolver was reached before adapter binding")


class _NeverEffect:
    def __init__(self) -> None:
        self.calls = 0

    def __getattr__(self, _name: str) -> object:
        self.calls += 1
        raise AssertionError("downstream effect was reached after a rejected binding")


@pytest.mark.parametrize(
    ("dto", "resolver_method"),
    (
        (ResolvedGateCInput, "resolve_gate_c"),
        (ResolvedPostCInput, "resolve_post_c"),
        (ResolvedGateDInput, "resolve_gate_d"),
        (ResolvedGateEInput, "resolve_gate_e"),
        (ResolvedGateFInput, "resolve_gate_f"),
    ),
)
def test_each_gate_artifact_is_a_frozen_typed_dto(dto: type[object], resolver_method: str) -> None:
    assert is_dataclass(dto)
    assert getattr(dto, "__dataclass_params__", None).frozen is True
    assert all(field.type is not object for field in fields(dto))
    assert resolver_method.startswith("resolve_")


def test_resolver_protocols_are_per_gate_and_have_no_generic_object_resolver() -> None:
    from role_radar.evaluation import r2_operational_artifacts as artifacts

    protocols = (
        artifacts.R2GateCResolver,
        artifacts.R2PostCResolver,
        artifacts.R2GateDResolver,
        artifacts.R2GateEResolver,
        artifacts.R2GateFResolver,
    )
    for protocol in protocols:
        assert "resolve" not in protocol.__dict__
        methods = [name for name in protocol.__dict__ if name.startswith("resolve_")]
        assert len(methods) == 1
        method = getattr(protocol, methods[0])
        assert inspect.signature(method).return_annotation is not object
        assert get_type_hints(method)["return"].__name__.startswith("Resolved")


@pytest.mark.parametrize(
    ("filename", "effect_names"),
    (
        ("r2_operational_gate_c_adapter.py", ("execute_gate_c_report_only",)),
        ("r2_operational_post_c_adapter.py", ("preregister_post_c",)),
        ("r2_operational_gate_d_adapter.py", ("execute_gate_d_bounded_acquisition",)),
        ("r2_operational_gate_e_adapter.py", ("run_gate_e_offline_preview",)),
        ("r2_operational_gate_f_adapter.py", ("run_gate_f_materialization_freeze",)),
    ),
)
def test_each_adapter_has_one_authority_invocation_and_no_successor(
    filename: str, effect_names: tuple[str, ...]
) -> None:
    root = Path(__file__).parents[2] / "src/role_radar/evaluation"
    tree = ast.parse((root / filename).read_text(encoding="utf-8"))
    calls = [
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    for effect_name in effect_names:
        assert calls.count(effect_name) == 1
    assert not {"run_all", "successor", "coordinator", "delegate"} & set(calls)


def test_effect_seams_are_gate_specific() -> None:
    root = Path(__file__).parents[2] / "src/role_radar/evaluation"
    d = ast.parse((root / "r2_operational_gate_d_adapter.py").read_text(encoding="utf-8"))
    e = ast.parse((root / "r2_operational_gate_e_adapter.py").read_text(encoding="utf-8"))
    f = ast.parse((root / "r2_operational_gate_f_adapter.py").read_text(encoding="utf-8"))

    d_calls = {
        node.func.attr
        for node in ast.walk(d)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert (
        d_calls == {"resolve_gate_d", "create", "run"}
        or {"resolve_gate_d", "create", "run"} <= d_calls
    )
    e_names = {node.id for node in ast.walk(e) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(e) if isinstance(node, ast.Attribute)
    }
    assert not e_names & {"provider", "writer", "materializer", "freezer", "create"}
    f_names = {node.id for node in ast.walk(f) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(f) if isinstance(node, ast.Attribute)
    }
    assert {"materializer", "freezer", "freeze_bindings_for_request"} <= f_names


@pytest.mark.parametrize(
    ("filename", "required_bindings"),
    (
        (
            "r2_operational_gate_c_adapter.py",
            (
                "expires_at_utc",
                "candidate_commit_sha256",
                "profile_sha256",
                "namespace",
                "approved_root",
            ),
        ),
        (
            "r2_operational_post_c_adapter.py",
            (
                "candidate_commit_sha256",
                "query_plan_sha256",
                "namespace",
                "approved_root",
                "selection_seed",
            ),
        ),
        (
            "r2_operational_gate_d_adapter.py",
            ("source_cap", "quota", "cardinality", "budget", "window_start_utc", "evidence_root"),
        ),
        (
            "r2_operational_gate_e_adapter.py",
            ("gate_d_request", "current_commit_sha256", "evidence_root", "budget_units"),
        ),
        (
            "r2_operational_gate_f_adapter.py",
            ("destination_root", "artifact_class", "current_commit_sha256", "provenance"),
        ),
    ),
)
def test_adapters_expose_explicit_cross_boundary_binding_guards(
    filename: str, required_bindings: tuple[str, ...]
) -> None:
    root = Path(__file__).parents[2] / "src/role_radar/evaluation"
    source = (root / filename).read_text(encoding="utf-8")
    assert all(binding in source for binding in required_bindings)


@pytest.mark.parametrize("gate", list(GateName))
def test_concrete_adapters_reject_gate_mismatch_before_resolver_or_effect(gate: GateName) -> None:
    packet = _packet(gate.value)
    capability = make_test_capability(packet)
    wrong_packet = _packet("c" if gate is not GateName.C else "post-c")
    resolver = _NeverResolver()
    effect = _NeverEffect()
    invokers = concrete_gate_invokers(
        c_resolver=resolver,
        provider=effect,
        post_c_resolver=resolver,
        writer=effect,
        d_resolver=resolver,
        d_factory=effect,
        e_resolver=resolver,
        f_resolver=resolver,
        materializer=effect,
        freezer=effect,
    )

    with pytest.raises(ValueError, match="binding_mismatch"):
        invokers.for_gate(gate).invoke(wrong_packet, capability)
    assert resolver.calls == 0
    assert effect.calls == 0


@pytest.mark.parametrize("gate", list(GateName))
def test_concrete_adapters_reject_capability_mismatch_before_resolver_or_effect(
    gate: GateName,
) -> None:
    packet = _packet(gate.value)
    capability = make_test_capability(packet)
    other = _packet(gate.value)
    object.__setattr__(other, "source_plan_sha256", "9" * 64)
    resolver = _NeverResolver()
    effect = _NeverEffect()
    invokers = concrete_gate_invokers(
        c_resolver=resolver,
        provider=effect,
        post_c_resolver=resolver,
        writer=effect,
        d_resolver=resolver,
        d_factory=effect,
        e_resolver=resolver,
        f_resolver=resolver,
        materializer=effect,
        freezer=effect,
    )

    with pytest.raises(ValueError, match="binding_mismatch"):
        invokers.for_gate(gate).invoke(other, capability)
    assert resolver.calls == 0
    assert effect.calls == 0


def test_post_c_rejects_resolved_gate_c_result_substitution_before_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from role_radar.evaluation import r2_operational_post_c_adapter as adapter

    authoritative = object()
    request = SimpleNamespace(
        gate_c_result=authoritative, source_plan=SimpleNamespace(source_plan_sha256="p")
    )
    resolved = SimpleNamespace(
        request=request,
        gate_c_result=object(),
        operation_id="op-r2-test",
        lineage_id="offline-lineage",
        source_plan_sha256="p",
    )
    writer = _NeverEffect()
    monkeypatch.setattr(adapter, "validate_post_c_request", lambda _request: None)
    monkeypatch.setattr(adapter, "preregister_post_c", lambda **_kwargs: writer)

    class Resolver:
        def resolve_post_c(self, _packet: object, _capability: object) -> object:
            return resolved

    with pytest.raises(ValueError, match="binding_mismatch"):
        adapter.invoke_post_c(
            _packet("post-c"), make_test_capability(_packet("post-c")), Resolver(), writer
        )
    assert writer.calls == 0


def test_gate_d_rejects_resolved_artifact_substitution_before_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from role_radar.evaluation import r2_operational_gate_d_adapter as adapter

    request = SimpleNamespace(
        post_c_request=SimpleNamespace(source_plan=object()), post_c_seal=object(), seeds=object()
    )
    resolved = SimpleNamespace(
        request=request,
        source_plan=object(),
        post_c_seal=request.post_c_seal,
        seeds=request.seeds,
    )
    factory = _NeverEffect()

    class Resolver:
        def resolve_gate_d(self, _packet: object, _capability: object) -> object:
            return resolved

    packet = _packet("d")
    with pytest.raises(ValueError, match="binding_mismatch"):
        adapter.invoke_gate_d(packet, make_test_capability(packet), Resolver(), factory)
    assert factory.calls == 0


def test_gate_e_rejects_resolved_gate_d_result_substitution_before_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from role_radar.evaluation import r2_operational_gate_e_adapter as adapter

    authoritative = object()
    request = SimpleNamespace(gate_d_result=authoritative)
    resolved = SimpleNamespace(request=request, gate_d_result=object())
    service = _NeverEffect()
    monkeypatch.setattr(adapter, "authorize_gate_e", lambda _request: None)
    monkeypatch.setattr(adapter, "run_gate_e_offline_preview", service)

    class Resolver:
        def resolve_gate_e(self, _packet: object, _capability: object) -> object:
            return resolved

    packet = _packet("e")
    with pytest.raises(ValueError, match="binding_mismatch"):
        adapter.invoke_gate_e(packet, make_test_capability(packet), Resolver())
    assert service.calls == 0


def test_gate_f_rejects_resolved_d_or_e_result_substitution_before_materializer_or_freezer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from role_radar.evaluation import r2_operational_gate_f_adapter as adapter

    request = SimpleNamespace(gate_d_result=object(), gate_e_result=object())
    resolved = SimpleNamespace(
        request=request, gate_d_result=object(), gate_e_result=request.gate_e_result
    )
    materializer = _NeverEffect()
    freezer = _NeverEffect()
    monkeypatch.setattr(adapter, "authorize_gate_f", lambda _request: None)
    monkeypatch.setattr(adapter, "run_gate_f_materialization_freeze", materializer)

    class Resolver:
        def resolve_gate_f(self, _packet: object, _capability: object) -> object:
            return resolved

    packet = _packet("f")
    with pytest.raises(ValueError, match="binding_mismatch"):
        adapter.invoke_gate_f(
            packet, make_test_capability(packet), Resolver(), materializer, freezer
        )
    assert materializer.calls == 0
    assert freezer.calls == 0


def test_composition_has_exactly_the_five_named_independent_adapters() -> None:
    resolver = _NeverResolver()
    effect = _NeverEffect()
    composed = concrete_gate_invokers(
        c_resolver=resolver,
        provider=effect,
        post_c_resolver=resolver,
        writer=effect,
        d_resolver=resolver,
        d_factory=effect,
        e_resolver=resolver,
        f_resolver=resolver,
        materializer=effect,
        freezer=effect,
    )
    assert type(composed.c) is ConcreteGateCInvoker
    assert type(composed.post_c) is ConcretePostCInvoker
    assert type(composed.d) is ConcreteGateDInvoker
    assert type(composed.e) is ConcreteGateEInvoker
    assert type(composed.f) is ConcreteGateFInvoker
    assert not hasattr(composed, "run_all")
    assert not hasattr(composed, "successor")


def test_operational_modules_and_cli_cannot_reach_forbidden_execution_edges() -> None:
    root = Path(__file__).parents[2]
    paths = (
        *(root / "src/role_radar/evaluation").glob("r2_operational*.py"),
        root / "src/role_radar/cli/evaluation_r2_operation.py",
    )
    forbidden = {
        "Settings",
        "DB",
        "LiveAcquisition",
        "F10.1C",
        "historical",
        "holdout",
        "R3",
        "scheduler",
        "socket",
        "httpx",
        "sqlalchemy",
        "network",
        "run_all",
        "coordinator",
        "Callable",
        "write_artifact",
        "AcquiredJobWriter",
        "open",
        "urlopen",
        "legacy",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert not (names & forbidden), path
