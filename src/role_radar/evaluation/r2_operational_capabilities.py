"""Closed, named capability boundary for the offline R2 seam."""

from __future__ import annotations

from dataclasses import dataclass

from .r2_operational_authorization import AuthorizationError, OperationPacket


@dataclass(frozen=True, slots=True)
class CapabilityVerification:
    """Result produced by an independent verifier/factory, not by a packet."""

    capability_name: str
    source_plan_sha256: str
    independently_verified: bool = True


class _CapabilityToken:
    pass


_CAPABILITY_TOKEN = _CapabilityToken()


@dataclass(frozen=True, slots=True, init=False)
class ProductionR2Capability:
    name: str
    source_plan_sha256: str
    independently_verified: bool
    _verification: CapabilityVerification

    def __init__(self, name: str, source_plan_sha256: str, _token: object = None) -> None:
        if _token is not _CAPABILITY_TOKEN:
            raise TypeError("capability must be produced by an independent verifier")
        verification = CapabilityVerification(name, source_plan_sha256)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "source_plan_sha256", source_plan_sha256)
        object.__setattr__(self, "independently_verified", verification.independently_verified)
        object.__setattr__(self, "_verification", verification)

    @classmethod
    def from_verification(
        cls, result: CapabilityVerification, *, _token: object = None
    ) -> ProductionR2Capability:
        if (
            not isinstance(result, CapabilityVerification)
            or result.independently_verified is not True
            or _token is not _CAPABILITY_TOKEN
        ):
            raise AuthorizationError("capability_mismatch")
        instance = cls(result.capability_name, result.source_plan_sha256, _CAPABILITY_TOKEN)
        object.__setattr__(instance, "_verification", result)
        return instance

    def verify_for(self, packet: OperationPacket) -> bool:
        result = self._verification
        return (
            result.independently_verified is True
            and result.capability_name == packet.capability_name
            and result.source_plan_sha256 == packet.source_plan_sha256
        )


class IndependentCapabilityVerifier:
    """The sole production construction path for the R2 capability."""

    def verify(self, capability_name: str, source_plan_sha256: str) -> ProductionR2Capability:
        result = CapabilityVerification(capability_name, source_plan_sha256)
        return ProductionR2Capability.from_verification(result, _token=_CAPABILITY_TOKEN)


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


__all__ = [
    "CapabilityVerification",
    "IndependentCapabilityVerifier",
    "ProductionR2Capability",
    "validate_capability",
]
