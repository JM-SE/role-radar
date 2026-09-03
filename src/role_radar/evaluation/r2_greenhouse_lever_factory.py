"""Fixed Greenhouse/Lever collector mapping for the D bridge."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

import httpx

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.lever import LeverCollector
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext
from role_radar.domain.enums import SourceType

from .profile_relevant_acquisition.source_plan import SourcePlan
from .r2_greenhouse_lever_capability import R2GreenhouseLeverCapability

_FAMILIES: Final = {"greenhouse", "lever"}


@dataclass(frozen=True, slots=True)
class R2GreenhouseLeverFactory:
    capability: R2GreenhouseLeverCapability
    plan: SourcePlan
    transport: httpx.AsyncBaseTransport

    def __post_init__(self) -> None:
        if type(self.capability) is not R2GreenhouseLeverCapability:
            raise ValueError("r2_operational_capability_required")
        if type(self.plan) is not SourcePlan or not isinstance(
            self.transport, httpx.AsyncBaseTransport
        ):
            raise ValueError("r2_operational_factory_invalid")
        claims = self.capability.claims
        if claims.source_plan_sha256 != self.plan.source_plan_sha256:
            raise ValueError("r2_source_plan_substitution")
        if (claims.budget, claims.per_board_cap, claims.per_company_cap) != (
            self.plan.budget.maximum,
            self.plan.per_board_cap,
            self.plan.per_company_cap,
        ):
            raise ValueError("r2_bounds_substitution")
        if any(item["family"] not in _FAMILIES for item in self.plan.source_configs):
            raise ValueError("r2_provider_family_rejected")

    def create(
        self, snapshot: SourceSnapshot, context: CollectorContext
    ) -> GreenhouseCollector | LeverCollector:
        expected = next(
            (
                item
                for item in self.plan.source_configs
                if item["source_key"] == snapshot.source_key
            ),
            None,
        )
        if expected is None or dict(cast(Mapping[str, object], expected["configuration"])) != dict(
            snapshot.configuration
        ):
            raise ValueError("r2_source_plan_substitution")
        if snapshot.source_type == SourceType.GREENHOUSE.value:
            return GreenhouseCollector(transport=context.transport, budget=context.budget)
        if snapshot.source_type == SourceType.LEVER.value:
            return LeverCollector(transport=context.transport, budget=context.budget)
        raise ValueError("r2_provider_family_rejected")

    def snapshots(self) -> tuple[SourceSnapshot, ...]:
        """Materialize only the canonical, already-bound plan entries."""
        return tuple(
            SourceSnapshot(
                source_id=f"ephemeral:{hashlib.sha256(str(item['source_key']).encode()).hexdigest()[:32]}",
                source_type=str(item["family"]),
                name=str(item["source_key"]),
                configuration=dict(cast(Mapping[str, object], item["configuration"])),
                source_key=str(item["source_key"]),
                configuration_version=int(cast(int, item["configuration_version"])),
            )
            for item in self.plan.source_configs
        )

    def runtime(self, budget: CollectionRunBudget) -> CollectorRuntime:
        return CollectorRuntime(transport=self.transport, budget=budget)


__all__ = ["R2GreenhouseLeverFactory"]
