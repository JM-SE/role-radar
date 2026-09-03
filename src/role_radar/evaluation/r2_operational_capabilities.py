"""Named, typed capability boundary; no provider construction occurs here."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .r2_operational_authorization import AuthorizationError, OperationPacket


@runtime_checkable
class R2OperationalCapability(Protocol):
    name: str
    source_plan_sha256: str
    independently_verified: bool

    def verify_for(self, packet: OperationPacket) -> bool: ...


@dataclass(frozen=True, slots=True)
class ProductionR2Capability:
    name: str
    source_plan_sha256: str
    independently_verified: bool = False

    def verify_for(self, packet: OperationPacket) -> bool:
        return (
            self.independently_verified
            and self.name == packet.capability_name
            and self.source_plan_sha256 == packet.source_plan_sha256
        )


def validate_capability(capability: object, packet: OperationPacket) -> R2OperationalCapability:
    if isinstance(capability, bool) or not isinstance(capability, R2OperationalCapability):
        raise AuthorizationError("capability_mismatch")
    try:
        valid = capability.verify_for(packet)
    except Exception as exc:
        raise AuthorizationError("capability_mismatch") from exc
    if valid is not True:
        raise AuthorizationError("capability_mismatch")
    return capability


__all__ = ["ProductionR2Capability", "R2OperationalCapability", "validate_capability"]
