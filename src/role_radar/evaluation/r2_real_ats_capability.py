"""Sealed, independently verified claims for the R2 public ATS boundary.

This module is deliberately pure.  It does not decode packets, resolve
credentials, construct transports, or perform collection.  The only way to
obtain an :class:`ApprovedRealATSCapability` is through an injected verifier.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Final, Protocol, cast

from role_radar.domain.enums import SourceType

from .profile_relevant_acquisition.source_plan import SourcePlan
from .r2_operational_authorization import OperationPacket
from .r2_operational_capabilities import ProductionR2Capability

REAL_ATS_HOSTS: Final[tuple[str, ...]] = (
    "boards-api.greenhouse.io",
    "api.lever.co",
    "api.eu.lever.co",
)
REAL_ATS_FAMILIES: Final[tuple[str, ...]] = ("greenhouse", "lever")
REAL_ATS_TIMEOUT_SECONDS: Final[float] = 120.0
_TOKEN = object()


class RealATSCapabilityError(ValueError):
    """Detail-free public failure for malformed or stale real claims."""

    def __init__(self, code: str = "real_ats_capability_rejected") -> None:
        self.code = code if code.startswith("real_ats_") else "real_ats_capability_rejected"
        super().__init__(self.code)


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    if type(value) in {str, int, bool, bytes, type(None)}:
        return value
    raise RealATSCapabilityError()


def _immutable(value: object) -> bool:
    if isinstance(value, MappingProxyType):
        return all(_immutable(key) and _immutable(child) for key, child in value.items())
    if type(value) is tuple:
        return all(_immutable(child) for child in value)
    return type(value) in {str, int, bool, bytes, type(None)}


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise RealATSCapabilityError()
    return value


def _valid_verification_values(values: dict[str, object]) -> bool:
    config_values = values["source_configs"]
    if type(config_values) is not tuple or any(
        type(item) is not MappingProxyType or not _immutable(item) for item in config_values
    ):
        return False
    for name in ("operation_id", "lineage_id", "namespace", "root"):
        if type(values[name]) is not str:
            return False
    for name in ("window_start", "window_cutoff", "expires_at"):
        value = values[name]
        if type(value) is not datetime or value.tzinfo is not UTC:
            return False
    for name in ("budget", "per_board_cap", "per_company_cap", "quota", "cardinality"):
        value = values[name]
        if type(value) is not int or isinstance(value, bool) or value < 0:
            return False
    return True


@dataclass(frozen=True, slots=True, init=False)
class RealATSVerification:
    """Opaque verifier output; callers cannot manufacture approval claims."""

    packet_sha256: str
    source_plan_sha256: str
    provider_families: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    source_configs: tuple[Mapping[str, object], ...]
    operation_id: str
    lineage_id: str
    namespace: str
    root: str
    window_start: datetime
    window_cutoff: datetime
    expires_at: datetime
    timeout_seconds: float
    budget: int
    per_board_cap: int
    per_company_cap: int
    quota: int
    cardinality: int

    def __init__(self, *args: object, _token: object = None, **kwargs: object) -> None:
        if _token is not _TOKEN:
            raise TypeError("real ATS verification is external-only")
        names = tuple(self.__dataclass_fields__)
        if len(args) > len(names) or set(kwargs) - set(names):
            raise TypeError("real ATS verification is malformed")
        values = dict(zip(names, args, strict=False)) | kwargs
        if set(values) != set(names):
            raise TypeError("real ATS verification is incomplete")
        if (
            type(values["packet_sha256"]) is not str
            or type(values["source_plan_sha256"]) is not str
            or type(values["provider_families"]) is not tuple
            or type(values["allowed_hosts"]) is not tuple
            or not _valid_verification_values(values)
            or type(values["timeout_seconds"]) is not float
            or values["timeout_seconds"] <= 0
        ):
            raise TypeError("real ATS verification is malformed")
        for name, value in values.items():
            object.__setattr__(self, name, value)


class RealATSVerifier(Protocol):
    """Independent boundary.  It may verify, but never collect or persist."""

    def verify_real_ats(self, packet: OperationPacket, plan: SourcePlan) -> RealATSVerification: ...


@dataclass(frozen=True, slots=True, init=False)
class ApprovedRealATSCapability:
    """Immutable, exact-scope real ATS capability."""

    claims: RealATSVerification
    production: ProductionR2Capability

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("real ATS capability must be verifier-produced")

    @classmethod
    def _from_verified(
        cls,
        claims: RealATSVerification,
        production: ProductionR2Capability,
        *,
        _token: object = None,
    ) -> ApprovedRealATSCapability:
        if (
            _token is not _TOKEN
            or type(claims) is not RealATSVerification
            or type(production) is not ProductionR2Capability
        ):
            raise RealATSCapabilityError()
        instance = object.__new__(cls)
        object.__setattr__(instance, "claims", claims)
        object.__setattr__(instance, "production", production)
        return instance

    def verify_for(self, packet: OperationPacket, plan: SourcePlan, *, now: datetime) -> None:
        c = self.claims
        try:
            if type(packet) is not OperationPacket or type(plan) is not SourcePlan:
                raise RealATSCapabilityError()
            plan.__post_init__()
            packet_now = packet.window_start.astimezone(UTC)
            current = _utc(now).astimezone(UTC)
            if (
                packet.gate != "d"
                or not self.production.verify_for(packet)
                or c.packet_sha256 != packet.packet_sha256
                or c.source_plan_sha256 != plan.source_plan_sha256 != packet.source_plan_sha256
                or c.provider_families != REAL_ATS_FAMILIES
                or c.allowed_hosts != REAL_ATS_HOSTS
                or c.operation_id != packet.operation_id != plan.operation_id
                or c.lineage_id != packet.lineage_id != plan.lineage_id
                or c.namespace != packet.destination_namespace != plan.namespace
                or c.root != packet.destination_root != plan.root
                or (c.window_start, c.window_cutoff, c.expires_at)
                != (
                    packet.window_start.astimezone(UTC),
                    packet.window_cutoff.astimezone(UTC),
                    packet.expires_at.astimezone(UTC),
                )
                or c.timeout_seconds != REAL_ATS_TIMEOUT_SECONDS
                or (c.budget, c.per_board_cap, c.per_company_cap)
                != (plan.budget.maximum, plan.per_board_cap, plan.per_company_cap)
                or (c.quota, c.cardinality) != (packet.quota, packet.cardinality)
                or current < c.window_start
                or current > c.window_cutoff
                or current >= c.expires_at
                or packet_now < c.window_start
                or not _source_configs_match(c.source_configs, plan)
            ):
                raise RealATSCapabilityError()
        except RealATSCapabilityError:
            raise
        except Exception as exc:
            raise RealATSCapabilityError() from exc


def _source_configs_match(configs: tuple[Mapping[str, object], ...], plan: SourcePlan) -> bool:
    if not configs or configs != tuple(_freeze(item) for item in plan.source_configs):
        return False
    seen: set[str] = set()
    for item in configs:
        if set(item) != {"family", "source_key", "configuration_version", "configuration"}:
            return False
        family = item["family"]
        if family not in REAL_ATS_FAMILIES or type(family) is not str:
            return False
        if (
            type(item["source_key"]) is not str
            or item["source_key"] in seen
            or type(item["configuration_version"]) is not int
            or item["configuration_version"] != 1
        ):
            return False
        try:
            source_type = SourceType(family)
            from role_radar.sources.configuration import validate_configuration
            from role_radar.sources.identity import canonical_source_key

            config = validate_configuration(
                source_type,
                1,
                dict(cast(Mapping[str, object], item["configuration"])),
            )
            if canonical_source_key(source_type, config.model_dump()) != item["source_key"]:
                return False
        except (TypeError, ValueError, KeyError):
            return False
        seen.add(item["source_key"])
    return True


def capability_from_independent_verifier(
    packet: OperationPacket,
    plan: SourcePlan,
    production: ProductionR2Capability,
    verifier: RealATSVerifier,
) -> ApprovedRealATSCapability:
    if type(packet) is not OperationPacket or type(plan) is not SourcePlan:
        raise RealATSCapabilityError()
    if verifier is None or not callable(getattr(verifier, "verify_real_ats", None)):
        raise RealATSCapabilityError("real_ats_verifier_required")
    try:
        # Dataclasses can be mutated through object.__setattr__; the verifier
        # must never be asked to bless an unvalidated graph.
        packet.__post_init__()
        plan.__post_init__()
        claims = verifier.verify_real_ats(packet, plan)
    except Exception as exc:
        raise RealATSCapabilityError() from exc
    if type(claims) is not RealATSVerification:
        raise RealATSCapabilityError()
    capability = ApprovedRealATSCapability._from_verified(claims, production, _token=_TOKEN)
    capability.verify_for(packet, plan, now=packet.window_start)
    return capability


def make_test_real_ats_verification(
    packet: OperationPacket, plan: SourcePlan
) -> RealATSVerification:
    """Build only verifier output for an offline fake verifier.

    The capability still must be produced through
    :func:`capability_from_independent_verifier`; this helper performs no
    approval and creates no transport.
    """
    if type(packet) is not OperationPacket or type(plan) is not SourcePlan:
        raise RealATSCapabilityError()
    configs = tuple(cast(Mapping[str, object], _freeze(item)) for item in plan.source_configs)
    return RealATSVerification(
        packet.packet_sha256,
        plan.source_plan_sha256,
        REAL_ATS_FAMILIES,
        REAL_ATS_HOSTS,
        configs,
        packet.operation_id,
        plan.lineage_id,
        plan.namespace,
        plan.root,
        packet.window_start.astimezone(UTC),
        packet.window_cutoff.astimezone(UTC),
        packet.expires_at.astimezone(UTC),
        REAL_ATS_TIMEOUT_SECONDS,
        plan.budget.maximum,
        plan.per_board_cap,
        plan.per_company_cap,
        packet.quota,
        packet.cardinality,
        _token=_TOKEN,
    )


__all__ = [
    "REAL_ATS_FAMILIES",
    "REAL_ATS_HOSTS",
    "REAL_ATS_TIMEOUT_SECONDS",
    "ApprovedRealATSCapability",
    "RealATSCapabilityError",
    "RealATSVerification",
    "RealATSVerifier",
    "capability_from_independent_verifier",
    "make_test_real_ats_verification",
]
