"""Closed, named capability boundary for the offline R2 seam."""

from __future__ import annotations

from dataclasses import dataclass

from .r2_operational_authorization import AuthorizationError, OperationPacket


@dataclass(frozen=True, slots=True)
class CapabilityVerification:
    """Result produced by an independent verifier/factory, not by a packet."""

    capability_name: str
    source_plan_sha256: str
    independently_verified: bool


@dataclass(frozen=True, slots=True, init=False)
class ProductionR2Capability:
    name: str
    source_plan_sha256: str
    independently_verified: bool
    _verification: CapabilityVerification

    def __init__(
        self, name: str, source_plan_sha256: str, independently_verified: bool = False
    ) -> None:
        # Kept as a narrow compatibility constructor for existing offline tests.  The
        # service accepts this concrete type only; no structural/duck-typed values pass.
        verification = CapabilityVerification(name, source_plan_sha256, independently_verified)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "source_plan_sha256", source_plan_sha256)
        object.__setattr__(self, "independently_verified", verification.independently_verified)
        object.__setattr__(self, "_verification", verification)

    @classmethod
    def from_verification(cls, result: CapabilityVerification) -> ProductionR2Capability:
        if (
            not isinstance(result, CapabilityVerification)
            or result.independently_verified is not True
        ):
            raise AuthorizationError("capability_mismatch")
        instance = cls(result.capability_name, result.source_plan_sha256, True)
        object.__setattr__(instance, "_verification", result)
        return instance

    def verify_for(self, packet: OperationPacket) -> bool:
        result = self._verification
        return (
            result.independently_verified is True
            and result.capability_name == packet.capability_name
            and result.source_plan_sha256 == packet.source_plan_sha256
        )


def validate_capability(capability: object, packet: OperationPacket) -> ProductionR2Capability:
    if type(capability) is not ProductionR2Capability:
        raise AuthorizationError("capability_mismatch")
    try:
        valid = capability.verify_for(packet)
    except Exception as exc:
        raise AuthorizationError("capability_mismatch") from exc
    if valid is not True:
        raise AuthorizationError("capability_mismatch")
    return capability


__all__ = ["CapabilityVerification", "ProductionR2Capability", "validate_capability"]
