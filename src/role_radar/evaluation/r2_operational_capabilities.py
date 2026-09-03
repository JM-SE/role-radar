"""Closed capability boundary for the offline R2 seam.

The only production input is an injected verifier result.  The explicit test
factory below is the deliberately small offline seam; it is not a live
capability constructor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .r2_operational_authorization import AuthorizationError, OperationPacket


class ExternalCapabilityVerifier(Protocol):
    def verify(self, packet: OperationPacket) -> CapabilityVerification: ...


class _CapabilityToken:
    pass


_CAPABILITY_TOKEN = _CapabilityToken()


@dataclass(frozen=True, slots=True, init=False)
class CapabilityVerification:
    """Opaque result that only an external verifier boundary may create."""

    capability_name: str
    source_plan_sha256: str
    independently_verified: bool

    def __init__(
        self,
        capability_name: str,
        source_plan_sha256: str,
        independently_verified: bool = True,
        *,
        _token: object = None,
    ) -> None:
        if _token is not _CAPABILITY_TOKEN:
            raise TypeError("capability verification is external-only")
        object.__setattr__(self, "capability_name", capability_name)
        object.__setattr__(self, "source_plan_sha256", source_plan_sha256)
        object.__setattr__(self, "independently_verified", independently_verified)


@dataclass(frozen=True, slots=True, init=False)
class ProductionR2Capability:
    name: str
    source_plan_sha256: str
    independently_verified: bool
    _verification: CapabilityVerification

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("capability must be produced by an external verifier")

    @classmethod
    def _from_external_result(
        cls, result: CapabilityVerification, *, _token: object = None
    ) -> ProductionR2Capability:
        if (
            type(result) is not CapabilityVerification
            or result.independently_verified is not True
            or _token is not _CAPABILITY_TOKEN
        ):
            raise AuthorizationError("capability_mismatch")
        instance = object.__new__(cls)
        object.__setattr__(instance, "name", result.capability_name)
        object.__setattr__(instance, "source_plan_sha256", result.source_plan_sha256)
        object.__setattr__(instance, "independently_verified", True)
        object.__setattr__(instance, "_verification", result)
        return instance

    def verify_for(self, packet: OperationPacket) -> bool:
        result = self._verification
        return (
            result.independently_verified is True
            and result.capability_name == packet.capability_name
            and result.source_plan_sha256 == packet.source_plan_sha256
        )


def make_test_capability(packet: OperationPacket) -> ProductionR2Capability:
    """Explicit offline fake seam; never accepts caller-selected identities."""
    if type(packet) is not OperationPacket:
        raise AuthorizationError("capability_mismatch")
    result = CapabilityVerification(
        packet.capability_name,
        packet.source_plan_sha256,
        _token=_CAPABILITY_TOKEN,
    )
    return ProductionR2Capability._from_external_result(result, _token=_CAPABILITY_TOKEN)


def capability_from_external_verifier(
    packet: OperationPacket, verifier: ExternalCapabilityVerifier
) -> ProductionR2Capability:
    """Construct a capability only from a verifier result bound to this packet."""
    try:
        result = verifier.verify(packet)
    except Exception as exc:
        raise AuthorizationError("capability_mismatch") from exc
    if (
        type(result) is not CapabilityVerification
        or result.capability_name != packet.capability_name
        or result.source_plan_sha256 != packet.source_plan_sha256
    ):
        raise AuthorizationError("capability_mismatch")
    return ProductionR2Capability._from_external_result(result, _token=_CAPABILITY_TOKEN)


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
    "ExternalCapabilityVerifier",
    "ProductionR2Capability",
    "capability_from_external_verifier",
    "make_test_capability",
    "validate_capability",
]
