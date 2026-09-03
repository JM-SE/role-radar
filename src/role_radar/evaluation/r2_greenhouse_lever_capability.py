"""Sealed, D-only claims for the first R2 provider bridge.

This module deliberately contains no verifier implementation and performs no
I/O.  The only non-production constructor is the explicitly named test seam.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Final, Protocol, cast

from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import validate_configuration
from role_radar.sources.identity import canonical_source_key

from .profile_relevant_acquisition.source_plan import SourcePlan
from .r2_operational_authorization import AuthorizationError, OperationPacket
from .r2_operational_capabilities import ProductionR2Capability

ALLOWED_FAMILIES: Final[tuple[str, ...]] = ("greenhouse", "lever")
GREENHOUSE_HOSTS: Final[tuple[str, ...]] = ("boards-api.greenhouse.io",)
LEVER_HOSTS: Final[tuple[str, ...]] = ("jobs.lever.co", "jobs.eu.lever.co")
_TOKEN = object()


class GreenhouseLeverClaimsVerifier(Protocol):
    def verify_greenhouse_lever_claims(
        self, packet: OperationPacket, plan: SourcePlan
    ) -> GreenhouseLeverVerification: ...


@dataclass(frozen=True, slots=True, init=False)
class GreenhouseLeverVerification:
    """Opaque result which can only be made at an external-verifier seam."""

    provider_families: tuple[str, ...]
    source_plan_sha256: str
    operation_id: str
    lineage_id: str
    namespace: str
    root: str
    expires_at: datetime
    window_start: datetime
    window_cutoff: datetime
    allowed_hosts: tuple[str, ...]
    source_configs: tuple[Mapping[str, object], ...]
    budget: int
    per_board_cap: int
    per_company_cap: int

    def __init__(self, *args: object, _token: object = None, **kwargs: object) -> None:
        if _token is not _TOKEN:
            raise TypeError("Greenhouse/Lever claims are external-only")
        values = dict(zip(self.__dataclass_fields__, args, strict=True)) | kwargs
        for name, value in values.items():
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class R2GreenhouseLeverCapability:
    claims: GreenhouseLeverVerification
    production: ProductionR2Capability

    def __post_init__(self) -> None:
        if type(self.claims) is not GreenhouseLeverVerification:
            raise AuthorizationError("capability_mismatch")
        if type(self.production) is not ProductionR2Capability:
            raise AuthorizationError("capability_mismatch")

    def verify_for(self, packet: OperationPacket, plan: SourcePlan, *, now: datetime) -> None:
        c = self.claims
        if not self.production.verify_for(packet) or packet.gate != "d":
            raise AuthorizationError("capability_mismatch")
        if c.source_plan_sha256 != plan.source_plan_sha256 != packet.source_plan_sha256:
            raise AuthorizationError("binding_mismatch")
        if (c.operation_id, c.lineage_id, c.namespace, c.root) != (
            packet.operation_id,
            plan.lineage_id,
            packet.destination_namespace,
            packet.destination_root,
        ):
            raise AuthorizationError("binding_mismatch")
        current = now.astimezone(UTC)
        if current < c.window_start or current > c.window_cutoff or current >= c.expires_at:
            raise AuthorizationError("expired")
        if (c.window_start, c.window_cutoff, c.expires_at) != (
            packet.window_start.astimezone(UTC),
            packet.window_cutoff.astimezone(UTC),
            packet.expires_at.astimezone(UTC),
        ):
            raise AuthorizationError("binding_mismatch")
        if (c.budget, c.per_board_cap, c.per_company_cap) != (
            plan.budget.maximum,
            plan.per_board_cap,
            plan.per_company_cap,
        ):
            raise AuthorizationError("binding_mismatch")
        expected = _claims_from_plan(plan)
        if c.provider_families != ALLOWED_FAMILIES or c.source_configs != expected.source_configs:
            raise AuthorizationError("binding_mismatch")
        if c.allowed_hosts != expected.allowed_hosts:
            raise AuthorizationError("binding_mismatch")


def capability_from_external_verifier(
    packet: OperationPacket,
    plan: SourcePlan,
    production: ProductionR2Capability,
    verifier: GreenhouseLeverClaimsVerifier,
) -> R2GreenhouseLeverCapability:
    if type(packet) is not OperationPacket or type(plan) is not SourcePlan:
        raise AuthorizationError("capability_mismatch")
    try:
        result = verifier.verify_greenhouse_lever_claims(packet, plan)
    except Exception as exc:
        raise AuthorizationError("capability_mismatch") from exc
    if type(result) is not GreenhouseLeverVerification:
        raise AuthorizationError("capability_mismatch")
    capability = R2GreenhouseLeverCapability(result, production)
    capability.verify_for(packet, plan, now=packet.window_start)
    return capability


def _claims_from_plan(plan: SourcePlan) -> GreenhouseLeverVerification:
    configs = tuple(MappingProxyType(dict(item)) for item in plan.source_configs)
    families = tuple(str(item["family"]) for item in plan.source_configs)
    if not configs or any(family not in ALLOWED_FAMILIES for family in families):
        raise AuthorizationError("binding_mismatch")
    keys: set[str] = set()
    for family, item in zip(families, configs, strict=True):
        if item["configuration_version"] != 1:
            raise AuthorizationError("binding_mismatch")
        try:
            source_type = SourceType(family)
            config = validate_configuration(
                source_type, 1, dict(cast(Mapping[str, object], item["configuration"]))
            )
            if canonical_source_key(source_type, config.model_dump()) != item["source_key"]:
                raise ValueError("source key mismatch")
        except (TypeError, ValueError, KeyError) as exc:
            raise AuthorizationError("binding_mismatch") from exc
        if item["source_key"] in keys:
            raise AuthorizationError("binding_mismatch")
        keys.add(str(item["source_key"]))
    hosts = tuple(
        dict.fromkeys(
            host
            for family, item in zip(families, configs, strict=True)
            for host in (GREENHOUSE_HOSTS if family == "greenhouse" else LEVER_HOSTS)
        )
    )
    return GreenhouseLeverVerification(
        ALLOWED_FAMILIES,
        plan.source_plan_sha256,
        plan.operation_id,
        plan.lineage_id,
        plan.namespace,
        plan.root,
        datetime.max.replace(tzinfo=UTC),
        datetime.min.replace(tzinfo=UTC),
        datetime.max.replace(tzinfo=UTC),
        hosts,
        configs,
        plan.budget.maximum,
        plan.per_board_cap,
        plan.per_company_cap,
        _token=_TOKEN,
    )


def make_test_verification(
    packet: OperationPacket, plan: SourcePlan
) -> GreenhouseLeverVerification:
    """Offline-only sealed fake; it is not an approval or production verifier."""
    base = _claims_from_plan(plan)
    return GreenhouseLeverVerification(
        base.provider_families,
        base.source_plan_sha256,
        base.operation_id,
        base.lineage_id,
        base.namespace,
        base.root,
        packet.expires_at,
        packet.window_start,
        packet.window_cutoff,
        base.allowed_hosts,
        base.source_configs,
        base.budget,
        base.per_board_cap,
        base.per_company_cap,
        _token=_TOKEN,
    )


__all__ = [
    "ALLOWED_FAMILIES",
    "GreenhouseLeverVerification",
    "R2GreenhouseLeverCapability",
    "capability_from_external_verifier",
    "make_test_verification",
]
