"""Fixed Greenhouse/Lever collector mapping for the D bridge."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

import httpx

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.lever import LeverCollector
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext
from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import validate_configuration
from role_radar.sources.identity import canonical_source_key

from .profile_relevant_acquisition.contracts import (
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
)
from .profile_relevant_acquisition.journal import AcquisitionJournal
from .profile_relevant_acquisition.journaled_transport import JournaledAsyncTransport
from .profile_relevant_acquisition.source_plan import SourcePlan
from .r2_greenhouse_lever_capability import (
    GREENHOUSE_HOSTS,
    LEVER_HOSTS,
    R2GreenhouseLeverCapability,
)
from .r2_operational_authorization import OperationPacket

_FAMILIES: Final = {"greenhouse", "lever"}
_TRANSPORT_TOKEN = object()


class R2GreenhouseLeverTestTransport(httpx.AsyncBaseTransport):
    """Closed, offline transport seam for the future provider bridge.

    It accepts fixed responses only.  There is deliberately no callback, client,
    resolver, or network fallback in this type.
    """

    __slots__ = ("_allowed_hosts", "_responses", "calls", "requests")

    def __init__(
        self,
        responses: Mapping[str, bytes],
        *,
        _token: object = None,
    ) -> None:
        if _token is not _TRANSPORT_TOKEN or type(responses) is not dict:
            raise TypeError("operational transport is test-seam only")
        self._responses = dict(responses)
        self._allowed_hosts: tuple[str, ...] = ()
        self.calls = 0
        self.requests: list[tuple[str, str]] = []

    def _seal_hosts(self, hosts: tuple[str, ...]) -> None:
        if self._allowed_hosts or not hosts:
            raise ValueError("r2_transport_already_bound")
        self._allowed_hosts = hosts

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.requests.append((request.url.host, request.url.path))
        if request.url.host not in self._allowed_hosts:
            return httpx.Response(403, request=request, content=b"{}")
        content = self._responses.get(request.url.path)
        if content is None:
            return httpx.Response(404, request=request, content=b"{}")
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "application/json"},
            content=content,
        )


def make_test_transport(responses: Mapping[str, bytes]) -> R2GreenhouseLeverTestTransport:
    """Create the only available operational transport, entirely offline."""
    return R2GreenhouseLeverTestTransport(responses, _token=_TRANSPORT_TOKEN)


@dataclass(frozen=True, slots=True)
class R2GreenhouseLeverFactory:
    capability: R2GreenhouseLeverCapability
    packet: OperationPacket
    plan: SourcePlan
    transport: R2GreenhouseLeverTestTransport

    def __post_init__(self) -> None:
        if type(self.capability) is not R2GreenhouseLeverCapability:
            raise ValueError("r2_operational_capability_required")
        if type(self.packet) is not OperationPacket or type(self.plan) is not SourcePlan:
            raise ValueError("r2_operational_factory_invalid")
        if type(self.transport) is not R2GreenhouseLeverTestTransport:
            raise ValueError("r2_operational_transport_rejected")
        try:
            self.plan.__post_init__()
            # Complete row validation must precede all host derivation and
            # transport mutation.
            self._validate_sources()
            self.capability.verify_for(self.packet, self.plan, now=self.packet.window_start)
        except Exception as exc:
            raise ValueError("r2_operational_binding_invalid") from exc
        claims = self.capability.claims
        if claims.source_plan_sha256 != self.plan.source_plan_sha256:
            raise ValueError("r2_source_plan_substitution")
        if (claims.budget, claims.per_board_cap, claims.per_company_cap) != (
            self.plan.budget.maximum,
            self.plan.per_board_cap,
            self.plan.per_company_cap,
        ):
            raise ValueError("r2_bounds_substitution")
        if tuple(claims.allowed_hosts) != tuple(
            dict.fromkeys(
                host
                for item in self.plan.source_configs
                for host in (GREENHOUSE_HOSTS if item["family"] == "greenhouse" else LEVER_HOSTS)
            )
        ):
            raise ValueError("r2_allowed_hosts_mismatch")
        self.transport._seal_hosts(claims.allowed_hosts)

    def _validate_sources(self) -> None:
        seen: set[str] = set()
        for item in self.plan.source_configs:
            try:
                if set(item) != {"family", "source_key", "configuration_version", "configuration"}:
                    raise ValueError("source shape mismatch")
                family = item["family"]
                if family not in _FAMILIES or type(family) is not str:
                    raise ValueError("family mismatch")
                if item["configuration_version"] != 1:
                    raise ValueError("version mismatch")
                key = item["source_key"]
                if type(key) is not str or key in seen:
                    raise ValueError("duplicate or invalid key")
                if not isinstance(item["configuration"], Mapping):
                    raise ValueError("configuration shape mismatch")
                source_type = SourceType(family)
                raw_configuration = cast(Mapping[str, object], item["configuration"])
                config = validate_configuration(source_type, 1, dict(raw_configuration))
                if canonical_source_key(source_type, config.model_dump()) != key:
                    raise ValueError("source key mismatch")
                seen.add(key)
            except (TypeError, ValueError, KeyError) as exc:
                raise ValueError("r2_source_configuration_invalid") from exc

    def create(
        self, snapshot: SourceSnapshot, context: CollectorContext
    ) -> GreenhouseCollector | LeverCollector:
        if type(context) is not CollectorContext:
            raise ValueError("r2_context_binding_invalid")
        if context.budget is not None and (
            type(context.budget) is not CollectionRunBudget
            or context.budget.maximum != self.plan.budget.maximum
        ):
            raise ValueError("r2_budget_binding_invalid")
        matches = [
            item for item in self.plan.source_configs if item["source_key"] == snapshot.source_key
        ]
        if len(matches) != 1:
            raise ValueError("r2_source_plan_substitution")
        expected = matches[0]
        if expected["family"] != snapshot.source_type:
            raise ValueError("r2_source_family_mismatch")
        if expected["configuration_version"] != snapshot.configuration_version:
            raise ValueError("r2_configuration_version_mismatch")
        if dict(cast(Mapping[str, object], expected["configuration"])) != dict(
            snapshot.configuration
        ):
            raise ValueError("r2_source_configuration_mismatch")
        # The runtime supplies the journal wrapper around this factory's sealed
        # transport.  Reject any unrelated context transport before construction.
        if type(context.transport) is not JournaledAsyncTransport or (
            getattr(context.transport, "_delegate", None) is not self.transport
        ):
            raise ValueError("r2_transport_binding_invalid")
        if snapshot.source_type == SourceType.GREENHOUSE.value:
            return GreenhouseCollector(transport=context.transport, budget=context.budget)
        if snapshot.source_type == SourceType.LEVER.value:
            return LeverCollector(transport=context.transport, budget=context.budget)
        raise ValueError("r2_provider_family_rejected")

    def create_effects(
        self,
        request: object,
        *,
        approval: ExternalApprovalBinding | None,
        approval_verifier: ExternalApprovalVerifier | None,
    ) -> object:
        """Build the named operational Gate D effects, fail closed by default."""
        from .profile_relevant_acquisition.gate_d_authorization import GateDAuthorizationRequest
        from .r2_operational_artifacts import GateDOperationalEffects

        if (
            type(request) is not GateDAuthorizationRequest
            or request.post_c_request.source_plan is not self.plan
        ):
            raise ValueError("r2_operational_binding_invalid")
        if not isinstance(approval, ExternalApprovalBinding) or approval_verifier is None:
            raise ValueError("r2_operational_approval_required")
        return GateDOperationalEffects(
            delegate=cast(Any, self.transport),
            factory=self,
            capability=self.capability,
            journal=AcquisitionJournal(
                operation_id=request.operation_id,
                root=Path(self.plan.root),
            ),
            approval=approval,
            approval_verifier=approval_verifier,
        )

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


@dataclass(frozen=True, slots=True)
class R2GreenhouseLeverCollectorFactory:
    """Named runtime factory; operational code never injects a free callable."""

    factory: R2GreenhouseLeverFactory

    def __post_init__(self) -> None:
        if type(self.factory) is not R2GreenhouseLeverFactory:
            raise TypeError("r2_operational_factory_required")

    def __call__(
        self, snapshot: SourceSnapshot, context: CollectorContext
    ) -> GreenhouseCollector | LeverCollector:
        return self.factory.create(snapshot, context)


__all__ = [
    "R2GreenhouseLeverCollectorFactory",
    "R2GreenhouseLeverFactory",
    "R2GreenhouseLeverTestTransport",
    "make_test_transport",
]
