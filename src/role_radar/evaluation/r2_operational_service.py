"""One-gate dispatcher. It deliberately has no successor/coordinator logic."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Protocol

from .r2_operational_authorization import (
    AuthorizationError,
    ExternalApprovalVerifier,
    OperationPacket,
    authorize_packet,
)
from .r2_operational_capabilities import validate_capability

PUBLIC_RESULT_FIELDS = frozenset({"gate", "operation_id", "status", "evidence_sha256"})


class GateLocalService(Protocol):
    def invoke(self, packet: OperationPacket, capability: object) -> Mapping[str, object]: ...


def dispatch_one_gate(
    *,
    packet: OperationPacket,
    capability: object,
    verifier: ExternalApprovalVerifier,
    gate_service: GateLocalService | None = None,
    now: datetime | None = None,
    used_nonces: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Validate all inputs before the single injected gate-local effect."""
    try:
        authorize_packet(
            packet,
            verifier,
            now=now or datetime.now(UTC),
            expected_gate=packet.gate,
            capability_name=getattr(capability, "name", None),
            used_nonces=used_nonces,
        )
        typed = validate_capability(capability, packet)
        if gate_service is None:
            return {"result": "blocked", "code": "blocked"}
        result = gate_service.invoke(packet, typed)
        if not isinstance(result, Mapping):
            raise AuthorizationError("blocked")
        safe = {
            str(key): value
            for key, value in result.items()
            if str(key) in PUBLIC_RESULT_FIELDS
            and (isinstance(value, (str, int, bool)) or value is None)
        }
        return {"result": "stopped", "code": "gate_completed", **safe}
    except AuthorizationError as exc:
        return {"result": "blocked", "code": exc.code}
    except Exception:
        return {"result": "blocked", "code": "blocked"}


__all__ = ["GateLocalService", "dispatch_one_gate"]
