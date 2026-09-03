"""Typed one-gate dispatcher; no coordinator or successor path exists here."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from .r2_operational_authorization import (
    AuthorizationError,
    CandidateCommitIdentityProvider,
    ExternalApprovalVerifier,
    OperationPacket,
    authorize_packet,
)
from .r2_operational_capabilities import ProductionR2Capability, validate_capability

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
    # Missing optional public evidence fields remain omitted for compatibility;
    # every value that is emitted is nevertheless typed and bound.
    result.setdefault("gate", packet.gate)
    if result["gate"] != packet.gate or not isinstance(result["gate"], str):
        raise AuthorizationError("blocked")
    for key in ("operation_id", "lineage_id"):
        field_value = result.get(key)
        if key in result and (
            not isinstance(field_value, str) or ID_RE.fullmatch(field_value) is None
        ):
            raise AuthorizationError("blocked")
        if key in result and field_value != getattr(packet, key):
            raise AuthorizationError("blocked")
    if "status" in result and result["status"] != TerminalStatus.STOPPED.value:
        raise AuthorizationError("blocked")
    if "evidence_sha256" in result and (
        not isinstance(result["evidence_sha256"], str)
        or HEX_RE.fullmatch(result["evidence_sha256"]) is None
    ):
        raise AuthorizationError("blocked")
    return {key: result[key] for key in allowed if key in result}


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
            return {"result": TerminalStatus.BLOCKED.value, "code": "blocked"}
        result = selected.invoke(packet, typed)
        if not isinstance(result, Mapping):
            raise AuthorizationError("blocked")
        return {
            "result": TerminalStatus.STOPPED.value,
            "code": "gate_completed",
            **_public_result(packet, result),
        }
    except AuthorizationError as exc:
        return {"result": TerminalStatus.BLOCKED.value, "code": exc.code}
    except Exception:
        return {"result": TerminalStatus.BLOCKED.value, "code": "blocked"}


__all__ = [
    "GateCInvoker",
    "GateDInvoker",
    "GateEInvoker",
    "GateFInvoker",
    "GateInvokers",
    "GateName",
    "PostCInvoker",
    "TerminalStatus",
    "dispatch_one_gate",
]
