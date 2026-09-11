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
from collections.abc import Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    ReportOnlyRequestEvidenceV1,
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


async def _open_search_provider(
    stack: AsyncExitStack,
    provider: Any,
) -> Any:
    """Enter one provider before exposing it to the search runtime."""

    try:
        if not callable(getattr(provider, "__aenter__", None)) or not callable(
            getattr(provider, "__aexit__", None)
        ):
            raise RuntimeError("provider lifecycle is not async-context-managed")
        return await stack.enter_async_context(provider)
    except Exception as exc:
        raise RealDiscoveryError("real_discovery_provider_open_failed") from exc


def _create_search_provider(
    factory: SearchProviderFactory,
    provider_name: str,
    api_key: str,
) -> Any:
    """Normalize factory failures before the search runtime can reserve quota."""

    try:
        return factory(provider_name, api_key)
    except Exception as exc:
        raise RealDiscoveryError("real_discovery_provider_open_failed") from exc


@dataclass(frozen=True, slots=True)
class RealDiscoveryResult:
    """Immutable provider result: verified configurations plus allowlisted evidence."""

    operation_id: str
    operation_sha256: str
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
    terminal_code: str | None = None
    counts: Mapping[str, int] | None = None
    truncation: Mapping[str, bool] | None = None
    requests: tuple[ReportOnlyRequestEvidenceV1, ...] = ()


ACCEPTED_REAL_DISCOVERY_STATES: frozenset[str] = frozenset(
    {"completed", "completed_partial"}
)
PARTIAL_REAL_DISCOVERY_TERMINAL_CODES: frozenset[str] = frozenset(
    {
        "board_verifications_exhausted",
        "multiple_budgets_exhausted",
        "unique_board_candidates_exhausted",
        "verification_wire_attempts_exhausted",
    }
)
MAX_REAL_SEARCH_REQUESTS = 8
MAX_REAL_CLASSIFIED_HITS = MAX_REAL_SEARCH_REQUESTS * 10
MAX_REAL_UNIQUE_BOARD_CANDIDATES = 10
MAX_REAL_UNIQUE_BOARD_CANDIDATES_SEEN = 100
MAX_REAL_BOARD_VERIFICATIONS = 8
MAX_REAL_WIRE_ATTEMPTS = 100
MAX_REAL_POSTINGS = 100_000


def _valid_counts(
    verified_sources: tuple[ReportOnlyVerifiedSourceV1, ...],
    counts: Mapping[str, int],
    truncation: Mapping[str, bool],
    *,
    query_count: object,
    brave_requests: object,
    tavily_requests: object,
    candidates_seen: object,
    verifications_attempted: object,
    wire_attempts_consumed: object,
) -> bool:
    expected_counts = {
        "search_requests_attempted",
        "search_requests_completed",
        "classified_hits",
        "unique_board_candidates_seen",
        "unique_board_candidates_retained",
        "board_verifications_attempted",
        "boards_verified",
        "verification_wire_attempts_consumed",
    }
    expected_truncation = {
        "unique_board_candidates",
        "board_verifications",
        "verification_wire_attempts",
    }
    if set(counts) != expected_counts or set(truncation) != expected_truncation:
        return False
    if any(type(value) is not int or value < 0 for value in counts.values()):
        return False
    if any(type(value) is not bool for value in truncation.values()):
        return False
    if (
        counts["search_requests_attempted"] > MAX_REAL_SEARCH_REQUESTS
        or counts["search_requests_completed"]
        > MAX_REAL_SEARCH_REQUESTS + MAX_REAL_BOARD_VERIFICATIONS
        or counts["search_requests_completed"] < counts["search_requests_attempted"]
        or counts["classified_hits"] > MAX_REAL_CLASSIFIED_HITS
        or counts["unique_board_candidates_seen"] > MAX_REAL_UNIQUE_BOARD_CANDIDATES_SEEN
        or counts["unique_board_candidates_retained"]
        != min(counts["unique_board_candidates_seen"], MAX_REAL_UNIQUE_BOARD_CANDIDATES)
        or counts["board_verifications_attempted"] > MAX_REAL_BOARD_VERIFICATIONS
        or counts["boards_verified"] > counts["board_verifications_attempted"]
        or counts["boards_verified"] != len(verified_sources)
        or counts["verification_wire_attempts_consumed"] > MAX_REAL_WIRE_ATTEMPTS
        or counts["verification_wire_attempts_consumed"]
        < counts["board_verifications_attempted"]
    ):
        return False
    ordinals = [source.board_candidate_ordinal for source in verified_sources]
    if len(set(ordinals)) != len(ordinals) or any(
        ordinal > counts["unique_board_candidates_retained"] for ordinal in ordinals
    ):
        return False
    if query_count is not None and (
        type(query_count) is not int or not 1 <= query_count <= MAX_REAL_SEARCH_REQUESTS // 2
    ):
        return False
    if query_count is not None and counts["search_requests_attempted"] > int(query_count) * 2:
        return False
    metadata = (
        brave_requests,
        tavily_requests,
        candidates_seen,
        verifications_attempted,
        wire_attempts_consumed,
    )
    if any(value is not None and type(value) is not int for value in metadata):
        return False
    if brave_requests is not None and tavily_requests is not None and (
        counts["search_requests_attempted"]
        != cast(int, brave_requests) + cast(int, tavily_requests)
    ):
        return False
    if candidates_seen is not None and candidates_seen != counts["unique_board_candidates_seen"]:
        return False
    if verifications_attempted is not None and verifications_attempted != counts[
        "board_verifications_attempted"
    ]:
        return False
    return wire_attempts_consumed is None or wire_attempts_consumed == counts[
        "verification_wire_attempts_consumed"
    ]


def has_usable_real_discovery_result(
    state: object,
    verified_sources: object,
    terminal_code: object = None,
    *,
    counts: object = None,
    truncation: object = None,
    query_count: object = None,
    brave_requests: object = None,
    tavily_requests: object = None,
    candidates_seen: object = None,
    verifications_attempted: object = None,
    wire_attempts_consumed: object = None,
) -> bool:
    """Return whether a bounded terminal result may cross the Gate C boundary."""

    if not (
        isinstance(state, str)
        and state in ACCEPTED_REAL_DISCOVERY_STATES
        and isinstance(verified_sources, tuple)
        and bool(verified_sources)
        and all(isinstance(item, ReportOnlyVerifiedSourceV1) for item in verified_sources)
    ):
        return False
    if state == "completed" and terminal_code is not None:
        return False
    if not isinstance(counts, Mapping) or not isinstance(truncation, Mapping):
        return False
    if not _valid_counts(
        verified_sources,
        counts,
        truncation,
        query_count=query_count,
        brave_requests=brave_requests,
        tavily_requests=tavily_requests,
        candidates_seen=candidates_seen,
        verifications_attempted=verifications_attempted,
        wire_attempts_consumed=wire_attempts_consumed,
    ):
        return False
    if state == "completed":
        return not any(truncation.values())
    if (
        not isinstance(terminal_code, str)
        or terminal_code not in PARTIAL_REAL_DISCOVERY_TERMINAL_CODES
    ):
        return False
    exhausted = {
        "unique_board_candidates_exhausted": counts["unique_board_candidates_seen"]
        >= MAX_REAL_UNIQUE_BOARD_CANDIDATES,
        "board_verifications_exhausted": counts["board_verifications_attempted"]
        >= MAX_REAL_BOARD_VERIFICATIONS,
        "verification_wire_attempts_exhausted": (
            counts["verification_wire_attempts_consumed"] >= MAX_REAL_WIRE_ATTEMPTS
        ),
    }
    if any(
        (truncation[name] and not exhausted[name + "_exhausted"])
        or (not truncation[name] and exhausted[name + "_exhausted"])
        for name in ("unique_board_candidates", "board_verifications", "verification_wire_attempts")
    ):
        return False
    active = [name for name, enabled in truncation.items() if enabled]
    if terminal_code == "multiple_budgets_exhausted":
        return len(active) >= 2 and all(exhausted[name + "_exhausted"] for name in active)
    if sum(truncation.values()) != 1:
        return False
    return (
        truncation[terminal_code.removesuffix("_exhausted")] is True
        and exhausted[terminal_code]
    )


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
        async with AsyncExitStack() as provider_stack:
            brave_provider = await _open_search_provider(
                provider_stack,
                _create_search_provider(factory, "brave", brave_key),
            )
            tavily_provider = await _open_search_provider(
                provider_stack,
                _create_search_provider(factory, "tavily", tavily_key),
            )
            search_capability = _sealed_search_capability(
                operation_id=operation.operation_id,
                operation_sha256=operation.operation_sha256,
                plan_sha256=operation.plan_sha256,
                # The inner report-only artifact currently has the library-wide
                # 24-hour maximum.  Live Gate C must remain bounded by the
                # independently verified operator authorization, which may be
                # shorter (the normal packet is 90 minutes).
                expires_at_utc=datetime.fromisoformat(
                    authorization.expires_at_utc.replace("Z", "+00:00")
                ),
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
                # Keep the production wall clock in the live composition.  An
                # explicit datetime is a deterministic test seam and disables
                # the runtime freshness guard by design.
                clock=clock,
            )
    except (ReportOnlyError, RuntimeCompositionError) as exc:
        raise RealDiscoveryError(getattr(exc, "code", "real_discovery_failed")) from exc
    except RealDiscoveryError:
        raise
    except Exception as exc:
        raise RealDiscoveryError("real_discovery_failed") from exc
    finally:
        # Secret material never leaves this function except into provider
        # memory, which is closed by the AsyncExitStack above. Local references
        # are dropped on every path, including exceptions. The result carries
        # hashes and counts.
        del brave_key, tavily_key

    if type(terminal) is not ReportOnlyTerminalReportV1:
        raise RealDiscoveryError("real_discovery_report_invalid")
    if not has_usable_real_discovery_result(
        terminal.state,
        terminal.verified_sources,
        terminal.terminal_code,
        counts=terminal.counts,
        truncation=terminal.truncation,
        query_count=len(plan.queries),
        brave_requests=sum(
            1
            for item in terminal.requests
            if item.kind == "search" and item.provider == "brave"
        ),
        tavily_requests=sum(
            1
            for item in terminal.requests
            if item.kind == "search" and item.provider == "tavily"
        ),
        candidates_seen=terminal.counts["unique_board_candidates_seen"],
        verifications_attempted=terminal.counts["board_verifications_attempted"],
        wire_attempts_consumed=terminal.counts["verification_wire_attempts_consumed"],
    ):
        raise RealDiscoveryError("real_discovery_no_verified_boards")
    if len(terminal.verified_sources) > 8:
        raise RealDiscoveryError("real_discovery_report_invalid")
    counts = terminal.counts
    search_requests = tuple(item for item in terminal.requests if item.kind == "search")
    try:
        return RealDiscoveryResult(
            operation_id=terminal.operation_id,
            operation_sha256=terminal.operation_sha256,
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
            terminal_code=terminal.terminal_code,
            counts=dict(counts),
            truncation=dict(terminal.truncation),
            requests=tuple(terminal.requests),
        )
    except (TypeError, ValueError) as exc:
        raise RealDiscoveryError("real_discovery_report_invalid") from exc


def run_real_gate_c_discovery_sync(
    **kwargs: Any,
) -> RealDiscoveryResult:
    """Synchronous wrapper for the single async discovery run."""

    return asyncio.run(run_real_gate_c_discovery(**kwargs))


__all__ = [
    "ACCEPTED_REAL_DISCOVERY_STATES",
    "PARTIAL_REAL_DISCOVERY_TERMINAL_CODES",
    "RealDiscoveryError",
    "RealDiscoveryResult",
    "has_usable_real_discovery_result",
    "run_real_gate_c_discovery",
    "run_real_gate_c_discovery_sync",
]
