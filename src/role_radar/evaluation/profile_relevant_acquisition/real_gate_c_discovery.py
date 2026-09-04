"""Real Gate C discovery composition: exactly one v2 report-only run.

This module owns provider/credential lifetimes and invokes one existing v2
report-only discovery. It never authorizes gates, builds ``SourcePlan``
objects, publishes outside the existing report-only evidence, writes
Source/Job rows, or chains successors.

Credentials are resolved only here, after all validation, through the
existing secure resolver seam. Secret values never cross this module's
output boundary.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    ReportOnlyTerminalReportV1,
    ReportOnlyVerifiedSourceV1,
)
from role_radar.continuous_acquisition.discovery_budget_v2 import DiscoveryBudgetV2
from role_radar.continuous_acquisition.providers import (
    BoundedCollectorProvider,
    ReportOnlyATSVerifier,
    SearchAuthorizationCapability,
)
from role_radar.continuous_acquisition.report_only_v2 import (
    ReportOnlyError,
    prepare_report_only_operation,
    verify_report_only_authorization,
)
from role_radar.continuous_acquisition.runtime_discovery_v2 import (
    RuntimeCompositionError,
    build_search_runtime,
    execute_report_only_runtime,
)
from role_radar.discovery.board_candidates import BoardCandidateV2
from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2

from .gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
)
from .real_discovery_capability import (
    ApprovedRealDiscoveryCapability,
    RealDiscoveryCapabilityError,
)


class RealDiscoveryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CredentialResolverProtocol(Protocol):
    def text(self, handle: object) -> str: ...


class SearchProviderFactory(Protocol):
    def __call__(self, provider_name: str, api_key: str) -> Any: ...


class QuotaAdapterProtocol(Protocol):
    def reserve_and_start_v2(self, *, operation_key: str, **kwargs: Any) -> Any: ...
    def finalize_v2(self, *, reservation_id: str, **kwargs: Any) -> Any: ...
    def revalidate_context_v2(self, **kwargs: Any) -> Any: ...
    def commit_v2(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RealDiscoveryResult:
    """Immutable provider result: verified configurations plus allowlisted evidence."""

    operation_id: str
    plan_sha256: str
    report_sha256: str
    state: str
    verified_sources: tuple[ReportOnlyVerifiedSourceV1, ...]
    query_count: int
    brave_requests: int
    tavily_requests: int
    candidates_seen: int
    verifications_attempted: int
    wire_attempts_consumed: int


def _default_provider_factory(provider_name: str, api_key: str) -> Any:
    if provider_name == "brave":
        from role_radar.discovery.providers.brave import BraveSearchProvider

        return BraveSearchProvider(api_key)
    if provider_name == "tavily":
        from role_radar.discovery.providers.tavily import TavilySearchProvider

        return TavilySearchProvider(api_key)
    raise RealDiscoveryError("real_discovery_provider_invalid")


def _free_quota(config: object, field: str) -> Any:
    quota = getattr(config, field, None)
    if quota is None and isinstance(config, dict):
        quota = config.get(field)
    if quota is None:
        raise RealDiscoveryError("real_discovery_quota_unavailable")
    enabled = quota.enabled if hasattr(quota, "enabled") else quota.get("enabled")
    if enabled is not True:
        raise RealDiscoveryError("real_discovery_quota_unavailable")
    return quota


def _utc_now(value: datetime | Callable[[], datetime] | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if callable(value):
        resolved = value()
        if type(resolved) is not datetime or resolved.tzinfo is not UTC:
            raise RealDiscoveryError("real_discovery_clock_invalid")
        return resolved
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise RealDiscoveryError("real_discovery_clock_invalid")
    return value


def _sealed_search_capability(
    *,
    operation_id: str,
    operation_sha256: str,
    plan_sha256: str,
    expires_at_utc: datetime,
    authorization_sha256: str | None,
) -> SearchAuthorizationCapability:
    capability = object.__new__(SearchAuthorizationCapability)
    object.__setattr__(capability, "operation_id", operation_id)
    object.__setattr__(capability, "operation_sha256", operation_sha256)
    object.__setattr__(capability, "plan_sha256", plan_sha256)
    object.__setattr__(capability, "expires_at_utc", expires_at_utc)
    object.__setattr__(capability, "allowed_providers", ("brave", "tavily"))
    object.__setattr__(capability, "authorization_sha256", authorization_sha256)
    return capability


async def run_real_gate_c_discovery(
    *,
    capability: ApprovedRealDiscoveryCapability,
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: DiscoveryQueryPlanV2,
    config: object,
    resolver: CredentialResolverProtocol,
    quota_adapter: QuotaAdapterProtocol,
    artifact_root: Path,
    provider_factory: SearchProviderFactory | None = None,
    collector_transport: object | None = None,
    collector_factory: Callable[..., Any] | None = None,
    clock: datetime | Callable[[], datetime] | None = None,
    nonce_source: Callable[[], bytes] | None = None,
    now: datetime | None = None,
) -> RealDiscoveryResult:
    """Validate everything, then run exactly one report-only discovery."""

    if type(capability) is not ApprovedRealDiscoveryCapability:
        raise RealDiscoveryError("real_discovery_capability_required")
    if type(authorization) is not GateCAuthorization:
        raise RealDiscoveryError("real_discovery_authorization_required")
    if type(accepted_b) is not AcceptedGateBBinding:
        raise RealDiscoveryError("real_discovery_gate_b_required")
    if type(plan) is not DiscoveryQueryPlanV2:
        raise RealDiscoveryError("real_discovery_plan_required")
    if not isinstance(artifact_root, Path) or artifact_root != Path(
        authorization.provenance.approved_root
    ):
        raise RealDiscoveryError("real_discovery_root_mismatch")
    if resolver is None or not callable(getattr(resolver, "text", None)):
        raise RealDiscoveryError("real_discovery_resolver_required")
    if quota_adapter is None or not callable(getattr(quota_adapter, "commit_v2", None)):
        raise RealDiscoveryError("real_discovery_quota_adapter_required")

    check_at = _utc_now(now)
    try:
        capability.verify_for(authorization, accepted_b, plan, config, now=check_at)
    except RealDiscoveryCapabilityError as exc:
        code = getattr(exc, "code", "real_discovery_capability_rejected")
        raise RealDiscoveryError(code) from exc

    try:
        operation = prepare_report_only_operation(
            plan,
            config,
            operation_id=authorization.operation_id,
            clock=clock if clock is not None else check_at,
            nonce_source=nonce_source,
            artifact_root=artifact_root,
        )
        report_authorization = verify_report_only_authorization(operation, now=check_at)
    except (ReportOnlyError, RuntimeCompositionError) as exc:
        raise RealDiscoveryError(getattr(exc, "code", "real_discovery_operation_invalid")) from exc
    except (TypeError, ValueError) as exc:
        raise RealDiscoveryError("real_discovery_operation_invalid") from exc

    brave_quota = _free_quota(config, "brave_free")
    tavily_quota = _free_quota(config, "tavily_free")

    def _handle(quota: Any) -> Any:
        return (
            quota.credential_handle
            if hasattr(quota, "credential_handle")
            else quota.get("credential_handle")
        )

    try:
        brave_key = resolver.text(_handle(brave_quota))
        tavily_key = resolver.text(_handle(tavily_quota))
    except Exception as exc:
        raise RealDiscoveryError("real_discovery_credential_unavailable") from exc

    factory = provider_factory or _default_provider_factory
    brave_provider: Any = None
    tavily_provider: Any = None
    try:
        if not brave_key or not tavily_key:
            raise RealDiscoveryError("real_discovery_credential_unavailable")
        brave_provider = factory("brave", brave_key)
        tavily_provider = factory("tavily", tavily_key)
        search_capability = _sealed_search_capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=operation.plan_sha256,
            expires_at_utc=report_authorization.expires_at_utc,
            authorization_sha256=report_authorization.authorization_sha256,
        )
        budget = DiscoveryBudgetV2()
        runtime = build_search_runtime(
            config,
            plan,
            authorization_capability=search_capability,
            execution_budget=budget,
            quota_adapter=quota_adapter,
        )
        runtime.brave = brave_provider
        runtime.tavily = tavily_provider
        collector_provider = BoundedCollectorProvider(transport=collector_transport)
        if collector_factory is not None:
            collector_provider.collector_factory = collector_factory
        verifier = ReportOnlyATSVerifier(
            collector_provider=collector_provider,
            operation_sha256=operation.operation_sha256,
        )

        async def _verify(candidate: object) -> ReportOnlyVerifiedSourceV1 | None:
            if not isinstance(candidate, BoardCandidateV2):
                return None
            return await verifier(candidate)

        terminal = await execute_report_only_runtime(
            operation,
            report_authorization,
            config,
            search_runtime=runtime,
            artifact_root=artifact_root,
            official_verifier=_verify,
            clock=clock if clock is not None else check_at,
        )
    except (ReportOnlyError, RuntimeCompositionError) as exc:
        raise RealDiscoveryError(getattr(exc, "code", "real_discovery_failed")) from exc
    except RealDiscoveryError:
        raise
    except Exception as exc:
        raise RealDiscoveryError("real_discovery_failed") from exc
    finally:
        for provider in (brave_provider, tavily_provider):
            closer = getattr(provider, "aclose", None)
            if callable(closer):
                with suppress(Exception):
                    await closer()
        # Secret material never leaves this function except into provider
        # memory, which is closed above. Local references are dropped on every
        # path, including exceptions. The result carries hashes and counts.
        del brave_key, tavily_key

    if type(terminal) is not ReportOnlyTerminalReportV1:
        raise RealDiscoveryError("real_discovery_report_invalid")
    if terminal.state != "completed" or not terminal.verified_sources:
        raise RealDiscoveryError("real_discovery_no_verified_boards")
    if len(terminal.verified_sources) > 8:
        raise RealDiscoveryError("real_discovery_report_invalid")
    counts = terminal.counts
    search_requests = tuple(item for item in terminal.requests if item.kind == "search")
    try:
        return RealDiscoveryResult(
            operation_id=terminal.operation_id,
            plan_sha256=terminal.plan_sha256,
            report_sha256=terminal.report_sha256,
            state=terminal.state,
            verified_sources=tuple(terminal.verified_sources),
            query_count=len(plan.queries),
            brave_requests=sum(1 for item in search_requests if item.provider == "brave"),
            tavily_requests=sum(1 for item in search_requests if item.provider == "tavily"),
            candidates_seen=int(counts.get("unique_board_candidates_seen", 0)),
            verifications_attempted=int(counts.get("board_verifications_attempted", 0)),
            wire_attempts_consumed=int(counts.get("verification_wire_attempts_consumed", 0)),
        )
    except (TypeError, ValueError) as exc:
        raise RealDiscoveryError("real_discovery_report_invalid") from exc


def run_real_gate_c_discovery_sync(
    **kwargs: Any,
) -> RealDiscoveryResult:
    """Synchronous wrapper for the single async discovery run."""

    return asyncio.run(run_real_gate_c_discovery(**kwargs))


__all__ = [
    "RealDiscoveryError",
    "RealDiscoveryResult",
    "run_real_gate_c_discovery",
    "run_real_gate_c_discovery_sync",
]
