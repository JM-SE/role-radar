"""Fixed Greenhouse/Lever collector mapping for the D bridge."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
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
from .profile_relevant_acquisition.post_c_preregistration_contracts import (
    validate_post_c_request,
)
from .profile_relevant_acquisition.source_plan import SourcePlan
from .r2_greenhouse_lever_capability import (
    GREENHOUSE_HOSTS,
    LEVER_HOSTS,
    R2GreenhouseLeverCapability,
)
from .r2_operational_authorization import OperationPacket
from .r2_real_ats_capability import ApprovedRealATSCapability
from .r2_real_ats_transport import (
    REAL_ATS_WIRE_LIMIT_BYTES,
    RealATSTestTransport,
    RealATSTransport,
    RealATSTransportError,
    _routes_from_source_configs,
    _validate_request,
)

_FAMILIES: Final = {"greenhouse", "lever"}
_TRANSPORT_TOKEN = object()


class R2GreenhouseLeverTestTransport(httpx.AsyncBaseTransport):
    """Closed, offline transport seam for the future provider bridge.

    It accepts fixed responses only.  There is deliberately no callback, client,
    resolver, or network fallback in this type.
    """

    __slots__ = (
        "_allowed_hosts",
        "_current_time",
        "_expires_at",
        "_max_requests",
        "_responses",
        "_routes",
        "_timeout_seconds",
        "_window_cutoff",
        "_window_start",
        "calls",
        "requests",
    )

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
        self._current_time: datetime | None = None
        self._expires_at: datetime | None = None
        self._max_requests = 0
        self._routes: tuple[tuple[str, str, str], ...] = ()
        self._timeout_seconds = 0.0
        self._window_cutoff: datetime | None = None
        self._window_start: datetime | None = None
        if any(
            type(value) is not bytes or len(value) > REAL_ATS_WIRE_LIMIT_BYTES
            for value in responses.values()
        ):
            raise RealATSTransportError("real_ats_response_limit")
        self.calls = 0
        self.requests: list[tuple[str, str]] = []

    def _seal_hosts(
        self,
        hosts: tuple[str, ...],
        source_configs: tuple[Mapping[str, object], ...],
        *,
        budget: int,
        timeout_seconds: float,
        window_start: datetime,
        window_cutoff: datetime,
        expires_at: datetime,
        current_time: datetime,
    ) -> None:
        if (
            self._allowed_hosts
            or not hosts
            or any(host not in (*GREENHOUSE_HOSTS, *LEVER_HOSTS) for host in hosts)
        ):
            raise ValueError("r2_transport_already_bound")
        routes = _routes_from_source_configs(source_configs)
        if any(host not in hosts for host, _path, _family in routes):
            raise RealATSTransportError("real_ats_host_binding_invalid")
        if (
            type(budget) is not int
            or budget <= 0
            or type(timeout_seconds) is not float
            or timeout_seconds <= 0
            or any(
                type(value) is not datetime or value.tzinfo is not UTC
                for value in (window_start, window_cutoff, expires_at, current_time)
            )
            or not window_start < expires_at <= window_cutoff
            or current_time < window_start
            or current_time > window_cutoff
            or current_time >= expires_at
        ):
            raise RealATSTransportError("r2_transport_binding_invalid")
        self._allowed_hosts = hosts
        self._routes = routes
        request_count = sum(1 if family == "greenhouse" else 6 for _, _, family in routes)
        self._max_requests = min(budget, request_count)
        self._timeout_seconds = timeout_seconds
        self._window_start = window_start
        self._window_cutoff = window_cutoff
        self._expires_at = expires_at
        self._current_time = current_time

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.requests.append((request.url.host, request.url.path))
        _validate_request(
            request,
            self._allowed_hosts,
            routes=self._routes,
            timeout_seconds=self._timeout_seconds,
        )
        if self.calls > self._max_requests:
            raise ValueError("r2_transport_request_budget_exhausted")
        if (
            self._current_time is None
            or self._window_start is None
            or self._window_cutoff is None
            or self._expires_at is None
            or self._current_time < self._window_start
            or self._current_time > self._window_cutoff
            or self._current_time >= self._expires_at
        ):
            raise RealATSTransportError("r2_transport_window_inactive")
        content = self._responses.get(request.url.path)
        if content is None:
            return httpx.Response(404, request=request, content=b"{}")
        if type(content) is not bytes or len(content) > REAL_ATS_WIRE_LIMIT_BYTES:
            raise RealATSTransportError("real_ats_response_limit")
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
    capability: R2GreenhouseLeverCapability | ApprovedRealATSCapability
    packet: OperationPacket
    plan: SourcePlan
    transport: R2GreenhouseLeverTestTransport | RealATSTransport | RealATSTestTransport
    current_time: datetime | None = None

    def __post_init__(self) -> None:
        from .r2_real_ats_capability import ApprovedRealATSCapability
        from .r2_real_ats_transport import RealATSTestTransport, RealATSTransport

        if type(self.capability) not in (R2GreenhouseLeverCapability, ApprovedRealATSCapability):
            raise ValueError("r2_operational_capability_required")
        if type(self.packet) is not OperationPacket or type(self.plan) is not SourcePlan:
            raise ValueError("r2_operational_factory_invalid")
        if type(self.transport) not in (
            R2GreenhouseLeverTestTransport,
            RealATSTransport,
            RealATSTestTransport,
        ):
            raise ValueError("r2_operational_transport_rejected")
        try:
            self.plan.__post_init__()
            # Complete row validation must precede all host derivation and
            # transport mutation.
            self._validate_sources()
            self.capability.verify_for(
                self.packet,
                self.plan,
                now=datetime.now(UTC) if self.current_time is None else self.current_time,
            )
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
        expected_hosts = (
            self._real_hosts()
            if type(self.capability) is ApprovedRealATSCapability
            else tuple(
                dict.fromkeys(
                    host
                    for item in self.plan.source_configs
                    for host in (
                        GREENHOUSE_HOSTS if item["family"] == "greenhouse" else LEVER_HOSTS
                    )
                )
            )
        )
        if tuple(claims.allowed_hosts) != expected_hosts:
            raise ValueError("r2_allowed_hosts_mismatch")
        if type(self.transport) in (RealATSTestTransport, R2GreenhouseLeverTestTransport):
            test_transport = cast(
                RealATSTestTransport | R2GreenhouseLeverTestTransport, self.transport
            )
            check = datetime.now(UTC) if self.current_time is None else self.current_time
            test_transport._seal_hosts(
                claims.allowed_hosts,
                self.plan.source_configs,
                budget=claims.budget,
                timeout_seconds=getattr(claims, "timeout_seconds", 120.0),
                window_start=claims.window_start,
                window_cutoff=claims.window_cutoff,
                expires_at=claims.expires_at,
                current_time=check.astimezone(UTC),
            )

    def _real_hosts(self) -> tuple[str, ...]:
        from .r2_real_ats_capability import REAL_ATS_HOSTS

        return REAL_ATS_HOSTS

    def _validate_sources(self) -> None:
        seen: set[str] = set()
        for item in self.plan.source_configs:
            try:
                if set(item) != {"family", "source_key", "configuration_version", "configuration"}:
                    raise ValueError("source shape mismatch")
                family = item["family"]
                if family not in _FAMILIES or type(family) is not str:
                    raise ValueError("family mismatch")
                if (
                    type(item["configuration_version"]) is not int
                    or item["configuration_version"] != 1
                ):
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
        now: datetime | None = None,
    ) -> object:
        """Build the named operational Gate D effects, fail closed by default."""
        from .profile_relevant_acquisition.gate_d_authorization import (
            GateDAuthorizationRequest,
            authorize_gate_d,
        )
        from .r2_operational_artifacts import GateDOperationalEffects

        if type(self.capability) is not ApprovedRealATSCapability:
            raise ValueError("r2_operational_capability_required")
        if type(self.transport) not in (RealATSTransport, RealATSTestTransport):
            raise ValueError("r2_operational_transport_rejected")
        if type(request) is not GateDAuthorizationRequest:
            raise ValueError("r2_operational_binding_invalid")
        check = datetime.now(UTC) if now is None else now
        try:
            # This is deliberately repeated at the final effect boundary.  A
            # resolver may return a graph whose frozen members were tampered
            # with after Post-C, so earlier validation is not sufficient.
            self.packet.__post_init__()
            validate_post_c_request(request.post_c_request)
            authorize_gate_d(request, now=check, allow_operational=True)
            post = request.post_c_request
            if (
                post.source_plan is not self.plan
                or post.gate_c_result.source_plan is not post.source_plan
                or post.gate_c_result.report is not post.gate_c_report
                or request.operation_id != self.packet.operation_id
                or request.lineage_id != self.packet.lineage_id
                or post.operation_id != self.packet.operation_id
                or post.lineage_id != self.packet.lineage_id
                or post.source_plan.source_plan_sha256 != self.packet.source_plan_sha256
                or post.query_plan.plan_sha256 != self.packet.query_plan_sha256
                or post.provenance.candidate_commit_sha256 != self.packet.commit_sha256
                or post.provenance.namespace != self.packet.destination_namespace
                or post.provenance.approved_root != self.packet.destination_root
                or post.seeds.selection_seed != self.packet.selection_seed_sha256
                or post.seeds.partition_seed != self.packet.partition_seed_sha256
                or post.accepted_gate_b.packet_sha256 != self.packet.b_ready_sha256
                or post.accepted_gate_b.packet.code_commit_sha256 != self.packet.commit_sha256
                or post.accepted_gate_b.packet.namespace != self.packet.destination_namespace
                or post.accepted_gate_b.packet.root != self.packet.destination_root
                or post.accepted_gate_b.packet.selection_seed != self.packet.selection_seed_sha256
                or post.accepted_gate_b.packet.partition_seed != self.packet.partition_seed_sha256
                or post.accepted_gate_b.packet.window_start_utc
                != self.packet.window_start.astimezone(UTC).isoformat().replace("+00:00", "Z")
                or post.accepted_gate_b.packet.window_end_utc
                != self.packet.window_cutoff.astimezone(UTC).isoformat().replace("+00:00", "Z")
                or post.accepted_gate_b.packet.per_board_cap != self.packet.source_cap
                or post.accepted_gate_b.packet.per_company_cap != self.packet.source_cap
                or post.accepted_gate_b.packet.budget_units != self.packet.budget
                or post.accepted_gate_b.packet.corpus_count != self.packet.cardinality
                or request.namespace != self.packet.destination_namespace
                or str(request.evidence_root) != self.packet.destination_root
                or request.window_start_utc
                != self.packet.window_start.astimezone(UTC).isoformat().replace("+00:00", "Z")
                or request.window_end_utc
                != self.packet.window_cutoff.astimezone(UTC).isoformat().replace("+00:00", "Z")
                or request.current_commit_sha256 != self.packet.commit_sha256
                or request.per_board_cap != self.packet.source_cap
                or request.per_company_cap != self.packet.source_cap
                or request.budget_units != self.packet.budget
                or request.cardinality["corpus"] != self.packet.cardinality
                or post.accepted_gate_b.packet.profile_sha256 != self.packet.profile_sha256
                or post.accepted_gate_b.packet.policy_sha256 != self.packet.policy_sha256
                or post.query_plan.profile_binding.canonical_profile_sha256
                != self.packet.profile_sha256
                or post.query_plan.policy_sha256 != self.packet.policy_sha256
            ):
                raise ValueError("r2_operational_binding_invalid")
        except Exception as exc:
            raise ValueError("r2_operational_binding_invalid") from exc
        if not isinstance(approval, ExternalApprovalBinding) or approval_verifier is None:
            raise ValueError("r2_operational_approval_required")
        self.capability.verify_for(
            self.packet,
            self.plan,
            now=check,
        )
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
        return CollectorRuntime(
            transport=cast(httpx.AsyncBaseTransport, self.transport), budget=budget
        )


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
