"""Typed one-gate dispatcher; no coordinator or successor path exists here."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from .r2_operational_artifacts import (
    R2Freezer,
    R2GateCResolver,
    R2GateDOfflineFactory,
    R2GateDResolver,
    R2GateEResolver,
    R2GateFResolver,
    R2Materializer,
    R2OfficialProvider,
    R2PostCResolver,
    R2PrivateSealWriter,
)
from .r2_operational_authorization import (
    PUBLIC_CODES,
    AuthorizationError,
    CandidateCommitIdentityProvider,
    ExternalApprovalVerifier,
    OperationPacket,
    authorize_packet,
)
from .r2_operational_capabilities import ProductionR2Capability, validate_capability
from .r2_operational_gate_c_adapter import invoke_gate_c
from .r2_operational_gate_d_adapter import invoke_gate_d
from .r2_operational_gate_e_adapter import invoke_gate_e
from .r2_operational_gate_f_adapter import invoke_gate_f
from .r2_operational_post_c_adapter import invoke_post_c

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class GateName(StrEnum):
    C = "c"
    POST_C = "post-c"
    D = "d"
    E = "e"
    F = "f"


class TerminalStatus(StrEnum):
    STOPPED = "stopped"
    BLOCKED = "blocked"


class GateInvoker(Protocol):
    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]: ...


class GateCInvoker(GateInvoker, Protocol):
    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]: ...


class PostCInvoker(GateInvoker, Protocol):
    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]: ...


class GateDInvoker(GateInvoker, Protocol):
    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]: ...


class GateEInvoker(GateInvoker, Protocol):
    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]: ...


class GateFInvoker(GateInvoker, Protocol):
    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class ConcreteGateCInvoker:
    resolver: R2GateCResolver
    provider: R2OfficialProvider

    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]:
        return invoke_gate_c(packet, capability, self.resolver, self.provider)


@dataclass(frozen=True, slots=True)
class ConcretePostCInvoker:
    resolver: R2PostCResolver
    writer: R2PrivateSealWriter

    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]:
        return invoke_post_c(packet, capability, self.resolver, self.writer)


@dataclass(frozen=True, slots=True)
class ConcreteGateDInvoker:
    resolver: R2GateDResolver
    factory: R2GateDOfflineFactory

    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]:
        return invoke_gate_d(packet, capability, self.resolver, self.factory)


@dataclass(frozen=True, slots=True)
class ConcreteGateEInvoker:
    resolver: R2GateEResolver

    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]:
        return invoke_gate_e(packet, capability, self.resolver)


@dataclass(frozen=True, slots=True)
class ConcreteGateFInvoker:
    resolver: R2GateFResolver
    materializer: R2Materializer
    freezer: R2Freezer

    def invoke(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> Mapping[str, object]:
        return invoke_gate_f(packet, capability, self.resolver, self.materializer, self.freezer)


def concrete_gate_invokers(
    *,
    c_resolver: R2GateCResolver,
    provider: R2OfficialProvider,
    post_c_resolver: R2PostCResolver,
    writer: R2PrivateSealWriter,
    d_resolver: R2GateDResolver,
    d_factory: R2GateDOfflineFactory,
    e_resolver: R2GateEResolver,
    f_resolver: R2GateFResolver,
    materializer: R2Materializer,
    freezer: R2Freezer,
) -> GateInvokers:
    """Compose only the five named, independently selectable adapters."""
    return GateInvokers(
        ConcreteGateCInvoker(c_resolver, provider),
        ConcretePostCInvoker(post_c_resolver, writer),
        ConcreteGateDInvoker(d_resolver, d_factory),
        ConcreteGateEInvoker(e_resolver),
        ConcreteGateFInvoker(f_resolver, materializer, freezer),
    )


@dataclass(frozen=True, slots=True)
class GateInvokers:
    c: GateCInvoker
    post_c: PostCInvoker
    d: GateDInvoker
    e: GateEInvoker
    f: GateFInvoker

    def for_gate(self, gate: GateName) -> GateInvoker:
        if gate is GateName.C:
            return self.c
        if gate is GateName.POST_C:
            return self.post_c
        if gate is GateName.D:
            return self.d
        if gate is GateName.E:
            return self.e
        if gate is GateName.F:
            return self.f
        raise AuthorizationError("gate_mismatch")


def _public_result(packet: OperationPacket, value: Mapping[str, object]) -> dict[str, object]:
    allowed = {"gate", "operation_id", "lineage_id", "status", "evidence_sha256"}
    if any(key not in allowed for key in value):
        raise AuthorizationError("blocked")
    result = dict(value)
    # Identity is mandatory in the public result, even when an injected gate
    # seam omitted it.  No internal DTO fields cross this boundary.
    result.setdefault("gate", packet.gate)
    result.setdefault("operation_id", packet.operation_id)
    result.setdefault("lineage_id", packet.lineage_id)
    result.setdefault("status", TerminalStatus.STOPPED.value)
    if result["gate"] != packet.gate or not isinstance(result["gate"], str):
        raise AuthorizationError("blocked")
    for key in ("operation_id", "lineage_id"):
        field_value = result.get(key)
        if not isinstance(field_value, str) or ID_RE.fullmatch(field_value) is None:
            raise AuthorizationError("blocked")
        if field_value != getattr(packet, key):
            raise AuthorizationError("blocked")
    if "status" in result and result["status"] != TerminalStatus.STOPPED.value:
        raise AuthorizationError("blocked")
    if "evidence_sha256" in result and (
        not isinstance(result["evidence_sha256"], str)
        or HEX_RE.fullmatch(result["evidence_sha256"]) is None
    ):
        raise AuthorizationError("blocked")
    return {key: result[key] for key in allowed if key in result}


def _blocked(packet: object, code: str) -> dict[str, object]:
    code = code if code in PUBLIC_CODES else "blocked"
    if isinstance(packet, OperationPacket):
        return {
            "result": TerminalStatus.BLOCKED.value,
            "code": code,
            "gate": packet.gate,
            "operation_id": packet.operation_id,
            "lineage_id": packet.lineage_id,
            "status": TerminalStatus.STOPPED.value,
        }
    return {"result": TerminalStatus.BLOCKED.value, "code": code}


def dispatch_one_gate(
    *,
    packet: OperationPacket,
    capability: object,
    verifier: ExternalApprovalVerifier,
    invokers: GateInvokers | None = None,
    candidate_provider: CandidateCommitIdentityProvider | None = None,
    now: datetime | None = None,
    used_nonces: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Authorize, select exactly one named invoker, invoke once, and STOP."""
    try:
        authorize_packet(
            packet,
            verifier,
            now=now or datetime.now(UTC),
            expected_gate=packet.gate,
            capability_name=capability.name
            if isinstance(capability, ProductionR2Capability)
            else None,
            candidate_provider=candidate_provider,
            used_nonces=used_nonces,
        )
        typed = validate_capability(capability, packet)
        selected = invokers.for_gate(GateName(packet.gate)) if invokers is not None else None
        if selected is None:
            return _blocked(packet, "blocked")
        result = selected.invoke(packet, typed)
        if not isinstance(result, Mapping):
            raise AuthorizationError("blocked")
        return {
            "result": TerminalStatus.STOPPED.value,
            "code": "gate_completed",
            **_public_result(packet, result),
        }
    except AuthorizationError as exc:
        return _blocked(packet, exc.code)
    except Exception as exc:
        code = getattr(exc, "code", "blocked")
        return _blocked(packet, code if isinstance(code, str) else "blocked")


__all__ = [
    "ConcreteGateCInvoker",
    "ConcreteGateDInvoker",
    "ConcreteGateEInvoker",
    "ConcreteGateFInvoker",
    "ConcretePostCInvoker",
    "GateCInvoker",
    "GateDInvoker",
    "GateEInvoker",
    "GateFInvoker",
    "GateInvokers",
    "GateName",
    "PostCInvoker",
    "TerminalStatus",
    "concrete_gate_invokers",
    "dispatch_one_gate",
]
