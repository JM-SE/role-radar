"""Injected bounded provider runtimes for the continuous source-only path.

This module intentionally contains adapters, not an alternative collector or
search implementation.  Network policy remains owned by the existing bounded
Greenhouse/Lever and Brave/Tavily adapters.  The objects below only translate
the continuous-context DTOs and discard provider payloads after each call.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from types import MappingProxyType
from typing import Literal, Protocol, cast

from role_radar.collectors.outcomes import CollectionFailure, CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import (
    CollectorRuntime,
    JobCollector,
)
from role_radar.collectors.protocols import (
    SourceSnapshot as CollectorSnapshot,
)
from role_radar.collectors.registry import CollectorContext, create_collector, validate_snapshot
from role_radar.continuous_acquisition.contracts import (
    DiscoveryCandidate,
    SourceSnapshot,
    VerifiedSource,
)
from role_radar.continuous_acquisition.discovery_artifacts_v2 import ReportOnlyVerifiedSourceV1
from role_radar.continuous_acquisition.discovery_budget_v2 import DiscoveryBudgetV2
from role_radar.discovery.authorization_v2 import canonical_json_bytes
from role_radar.discovery.board_candidates import (
    BoardCandidateV2,
    BoardSearchHitV2,
    classify_board_candidates,
)
from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    LeverOfficialCandidate,
    PlannedQuery,
    ProviderIntent,
    ProviderTier,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
)
from role_radar.discovery.planner_v2 import (
    DiscoveryQueryPlanV2,
    planned_query_v2_to_search_request,
)
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.discovery.url_classifier import classify_url
from role_radar.repositories.acquisition import (
    DiscoveryQuotaContextV2,
    DiscoveryQuotaContextV2Protocol,
    ProviderCallStartV2,
    ProviderCallTerminalV2,
    QuotaContextV2Input,
)
from role_radar.sources.identity import canonical_source_key


def collector_snapshot(snapshot: SourceSnapshot) -> CollectorSnapshot:
    """Convert and validate one continuous snapshot without opening I/O.

    Continuous snapshots use ``revision`` while the collector registry uses
    ``configuration_version``.  The registry is the authority for the latter;
    revision is deliberately not copied into the collector configuration.
    """

    if snapshot.revision < 1:
        raise ValueError("continuous source revision must be positive")
    candidate = CollectorSnapshot(
        source_id=snapshot.source_id,
        source_type=snapshot.source_type,
        name=snapshot.name,
        configuration=MappingProxyType(dict(snapshot.configuration)),
        source_key=snapshot.source_key,
        configuration_version=1,
    )
    return validate_snapshot(candidate)


@dataclass(slots=True)
class BoundedCollectorProvider:
    """Async source collector backed by the existing registry factories.

    A fresh collector is created for each source invocation.  No SQLAlchemy
    object and no normal pipeline writer crosses this seam.
    """

    transport: object | None = None
    clock: Callable[[], float] | None = None
    sleeper: Callable[[float], Awaitable[None]] | None = None
    user_agent: str = "role-radar/0.1 (+homelab)"
    budget: CollectionRunBudget | None = None
    collector_factory: Callable[[CollectorSnapshot, CollectorContext], JobCollector] = (
        create_collector
    )

    def set_budget(self, budget: CollectionRunBudget) -> None:
        """Allow AcquisitionService to install the run-shared wire budget."""

        self.budget = budget

    async def __call__(self, snapshot: SourceSnapshot) -> CollectionSuccess | CollectionFailure:
        normalized = collector_snapshot(snapshot)
        context = CollectorContext(
            transport=self.transport,  # type: ignore[arg-type]
            clock=self.clock,
            sleeper=self.sleeper,
            budget=self.budget,
            user_agent=self.user_agent,
        )
        collector = self.collector_factory(normalized, context)
        runtime = CollectorRuntime(
            transport=context.transport,
            clock=context.clock or CollectorRuntime().clock,
            sleeper=context.sleeper or CollectorRuntime().sleeper,
            budget=context.budget,
        )
        result = await collector.collect(normalized, runtime)
        if not isinstance(result, (CollectionSuccess, CollectionFailure)):
            raise TypeError("bounded collector returned a legacy result")
        return result


class SearchProvider(Protocol):
    provider: str

    async def search(self, request: SearchRequest) -> SearchResponse: ...


@dataclass(frozen=True, slots=True)
class SearchAuthorizationCapability:
    """Sealed, operation-bound capability required before provider I/O.

    A report-only evidence DTO is not itself executable authority.  The runtime
    composition root must explicitly create this capability after all offline
    checks and the start marker have passed.  ``BoundedSearchRuntime`` rejects
    arbitrary truthy objects rather than treating them as authorization.
    """

    operation_id: str
    operation_sha256: str
    plan_sha256: str
    expires_at_utc: datetime
    allowed_providers: tuple[Literal["brave", "tavily"], ...] = ("brave", "tavily")
    authorization_sha256: str | None = None

    def __post_init__(self) -> None:
        raise ValueError("discovery_v2_live_gate_blocked")

    def allows(
        self,
        *,
        operation_id: str,
        plan_sha256: str,
        provider: str,
        now: datetime,
    ) -> bool:
        current = now.astimezone(UTC)
        return (
            operation_id == self.operation_id
            and plan_sha256 == self.plan_sha256
            and provider in self.allowed_providers
            and current < self.expires_at_utc.astimezone(UTC)
        )


class SearchQuotaAdapter(Protocol):
    """Minimum durable quota seam used by the provider adapter."""

    def reserve_and_start_v2(
        self,
        *,
        operation_key: str,
        context: QuotaContextV2Input,
        start: ProviderCallStartV2,
    ) -> object | None: ...

    def finalize_v2(
        self,
        *,
        reservation_id: str,
        terminal: ProviderCallTerminalV2,
    ) -> object: ...

    def revalidate_context_v2(
        self,
        *,
        operation_id: str,
        plan_sha256: str,
        context: QuotaContextV2Input,
    ) -> DiscoveryQuotaContextV2: ...

    def commit_v2(self) -> None: ...


def _provider_context(
    contexts: tuple[DiscoveryQuotaContextV2Protocol, ...], provider: str
) -> DiscoveryQuotaContextV2Protocol | None:
    for context in contexts:
        if context.provider == provider:
            return context
    return None


def _reserve_and_start(
    adapter: SearchQuotaAdapter,
    *,
    operation_key: str,
    context: QuotaContextV2Input,
    start: ProviderCallStartV2,
) -> object | None:
    method = getattr(adapter, "reserve_and_start_v2", None) or getattr(
        adapter, "publish_reservation_and_ledger_start_v2", None
    )
    if not callable(method):
        raise RuntimeError("discovery_quota_adapter_required")
    return cast(object | None, method(operation_key=operation_key, context=context, start=start))


def _finalize(
    adapter: SearchQuotaAdapter,
    *,
    reservation_id: str,
    terminal: ProviderCallTerminalV2,
) -> object:
    method = getattr(adapter, "finalize_v2", None) or getattr(
        adapter, "finalize_reservation_and_ledger_v2", None
    )
    if not callable(method):
        raise RuntimeError("discovery_quota_adapter_required")
    return cast(object, method(reservation_id=reservation_id, terminal=terminal))


def _commit_boundary(adapter: SearchQuotaAdapter) -> None:
    method = getattr(adapter, "commit_v2", None) or getattr(adapter, "commit_boundary_v2", None)
    if not callable(method):
        raise RuntimeError("discovery_quota_adapter_required")
    method()


DISCOVERY_HOSTS = (
    "boards.greenhouse.io",
    "job-boards.greenhouse.io",
    "jobs.lever.co",
    "jobs.eu.lever.co",
)
MAX_DISCOVERY_QUERIES = 4
MAX_DISCOVERY_HITS = 10


@dataclass(slots=True)
class BoundedSearchRuntimeV1:
    """Transient Brave-first discovery with Tavily fallback.

    ``run`` returns only URL/rank candidates.  Plaintext queries and provider
    response bodies remain local to this object and are never sent to a store.
    """

    brave: SearchProvider | None = None
    tavily: SearchProvider | None = None
    query_secret: bytes | str = b"offline-test-query-key"
    planner_version: str = "continuous-discovery-v1"
    query_version: str = "continuous-discovery-v1"
    queries: tuple[PlannedQuery, ...] = ()
    last_status: str = field(default="unknown", init=False)

    async def run(self) -> tuple[DiscoveryCandidate, ...]:
        key_factory = QueryKeyFactory(self.query_secret)
        found: dict[str, DiscoveryCandidate] = {}
        observed_statuses: list[str] = []
        brave_calls = 0
        tavily_calls = 0
        for query in self.queries[:MAX_DISCOVERY_QUERIES]:
            request = SearchRequest(
                operation_key=f"continuous-discovery:{query.ordinal}",
                query=query.canonical_query,
                query_key=key_factory.key(query, planner_version=self.planner_version),
                planner_version=self.planner_version,
                query_version=self.query_version,
                max_results=MAX_DISCOVERY_HITS,
                provider_intent=ProviderIntent.EXACT,
                cycle_query_count=MAX_DISCOVERY_QUERIES,
            )
            response: SearchResponse | None = None
            if self.brave is not None and brave_calls < MAX_DISCOVERY_QUERIES:
                brave_calls += 1
                response = await self.brave.search(request)
            # Tavily is deliberately fallback-only: it gets the same bounded
            # request only when Brave is absent or did not yield a usable board.
            if (
                (response is None or response.status not in {"succeeded", "empty"})
                and self.tavily is not None
                and tavily_calls < MAX_DISCOVERY_QUERIES
            ):
                tavily_calls += 1
                response = await self.tavily.search(request)
            if response is None or response.status not in {"succeeded", "empty"}:
                if response is not None:
                    observed_statuses.append(response.status)
                continue
            observed_statuses.append(response.status)
            self._add_hits(found, response.hits[:MAX_DISCOVERY_HITS], response.provider)
        self.last_status = (
            "succeeded"
            if any(status in {"succeeded", "empty"} for status in observed_statuses)
            else "failed"
            if observed_statuses
            else "empty"
        )
        return tuple(sorted(found.values(), key=lambda item: (item.rank, item.url)))

    async def candidates_async(self) -> tuple[DiscoveryCandidate, ...]:
        return await self.run()

    @staticmethod
    def _add_hits(
        target: dict[str, DiscoveryCandidate],
        hits: Iterable[TransientSearchHit],
        provider: str,
    ) -> None:
        for hit in hits:
            if len(target) >= MAX_DISCOVERY_HITS:
                break
            # Classification is repeated by the verifier.  Doing this early
            # keeps unknown/rejected search URLs transient and out of stores.
            if not isinstance(
                classify_url(hit.url), (GreenhouseOfficialCandidate, LeverOfficialCandidate)
            ):
                continue
            target.setdefault(hit.url, DiscoveryCandidate(hit.url, provider, hit.rank))


@dataclass(slots=True)
class BoundedSearchRuntime:
    """Provider adapter that accepts only a verified v2 plan.

    The class never constructs profiles, queries, authorization, or quota
    contexts.  It only consumes already verified DTOs and the explicit durable
    quota seam supplied by the composition root.
    """

    plan: DiscoveryQueryPlanV2
    operation_id: str
    authorization: SearchAuthorizationCapability | None = None
    execution_budget: DiscoveryBudgetV2 | None = None
    quota_adapter: SearchQuotaAdapter | None = None
    quota_contexts: tuple[DiscoveryQuotaContextV2Protocol, ...] = ()
    before_transport_check: Callable[[], None] | None = None
    brave: SearchProvider | None = None
    tavily: SearchProvider | None = None
    last_responses: tuple[tuple[int, SearchResponse], ...] = ()
    unique_board_candidates_seen: int = field(default=0, init=False)
    candidate_truncated: bool = field(default=False, init=False)
    last_status: str = field(default="unknown", init=False)

    async def search(self) -> tuple[BoardCandidateV2, ...]:
        budget = self.execution_budget or DiscoveryBudgetV2()
        if not isinstance(self.authorization, SearchAuthorizationCapability):
            raise RuntimeError("discovery_v2_authorization_required")
        if self.authorization.plan_sha256 != self.plan.plan_sha256:
            raise RuntimeError("discovery_v2_authorization_invalid")
        if self.quota_adapter is None:
            raise RuntimeError("discovery_v2_quota_adapter_required")
        responses: list[tuple[int, SearchResponse]] = []
        for query in self.plan.queries:
            request = planned_query_v2_to_search_request(query, self.plan, self.operation_id)
            response: SearchResponse | None = None
            for provider_name, provider in (("brave", self.brave), ("tavily", self.tavily)):
                if provider is None or (
                    response is not None
                    and response.status in {"succeeded", "empty", "indeterminate"}
                ):
                    continue
                context = _provider_context(self.quota_contexts, provider_name)
                if context is None:
                    continue
                revalidate = getattr(self.quota_adapter, "revalidate_context_v2", None)
                if self.before_transport_check is not None:
                    self.before_transport_check()
                if callable(revalidate):
                    context = revalidate(
                        operation_id=self.operation_id,
                        plan_sha256=self.plan.plan_sha256,
                        context=context,
                    )
                if not self.authorization.allows(
                    operation_id=self.operation_id,
                    plan_sha256=self.plan.plan_sha256,
                    provider=provider_name,
                    now=datetime.now(UTC),
                ):
                    raise RuntimeError("discovery_v2_authorization_expired")
                budget.reserve_search(provider_name)
                durable_key = f"{request.operation_key}:{provider_name}"
                start = ProviderCallStartV2(
                    task_id=f"continuous-discovery-v2:{self.operation_id}",
                    operation_key=durable_key,
                    cycle_id=self.operation_id,
                    query_key=request.query_key,
                    query_ordinal=query.ordinal,
                    provider=provider_name,  # type: ignore[arg-type]
                    tier="free",
                    started_at=datetime.now(UTC),
                )
                publication = _reserve_and_start(
                    self.quota_adapter,
                    operation_key=durable_key,
                    context=context,
                    start=start,
                )
                if publication is None:
                    continue
                reservation_id = getattr(publication, "reservation_id", None)
                if not isinstance(reservation_id, str):
                    raise RuntimeError("discovery_quota_evidence_invalid")
                try:
                    _commit_boundary(self.quota_adapter)
                except Exception as exc:
                    raise RuntimeError("discovery_quota_evidence_invalid") from exc
                if callable(revalidate):
                    try:
                        if self.before_transport_check is not None:
                            self.before_transport_check()
                        context = revalidate(
                            operation_id=self.operation_id,
                            plan_sha256=self.plan.plan_sha256,
                            context=context,
                        )
                    except Exception as exc:
                        terminal = ProviderCallTerminalV2(
                            operation_key=durable_key,
                            status="failed",
                            transmission_status="not_sent",
                            candidate_count=0,
                            known_count=0,
                            unknown_count=0,
                            rejected_count=0,
                            duration_ms=0,
                            error_code="pretransport_failed",
                            completed_at=datetime.now(UTC),
                        )
                        _finalize(
                            self.quota_adapter,
                            reservation_id=reservation_id,
                            terminal=terminal,
                        )
                        _commit_boundary(self.quota_adapter)
                        raise RuntimeError("discovery_quota_evidence_invalid") from exc
                try:
                    response = await provider.search(request)
                except Exception as exc:
                    response = SearchResponse(
                        provider=provider_name,  # type: ignore[arg-type]
                        tier=ProviderTier.FREE,
                        status="indeterminate",
                        error_code="transmission_indeterminate",
                    )
                    responses.append((query.ordinal, response))
                    self.last_responses = tuple(responses)
                    terminal = ProviderCallTerminalV2(
                        operation_key=durable_key,
                        status="indeterminate",
                        transmission_status="indeterminate",
                        candidate_count=0,
                        known_count=0,
                        unknown_count=0,
                        rejected_count=0,
                        duration_ms=0,
                        error_code="transmission_indeterminate",
                        completed_at=datetime.now(UTC),
                    )
                    _finalize(
                        self.quota_adapter,
                        reservation_id=reservation_id,
                        terminal=terminal,
                    )
                    _commit_boundary(self.quota_adapter)
                    raise RuntimeError("transmission_indeterminate") from exc
                if response.provider != provider_name:
                    response = SearchResponse(
                        provider=provider_name,  # type: ignore[arg-type]
                        tier=response.tier,
                        status="malformed",
                        error_code="provider_malformed",
                    )
                terminal_status = response.status
                transmission = "indeterminate" if terminal_status == "indeterminate" else "sent"
                error_code = response.error_code or {
                    "failed": "provider_failed",
                    "malformed": "provider_malformed",
                    "indeterminate": "transmission_indeterminate",
                }.get(terminal_status)
                terminal = ProviderCallTerminalV2(
                    operation_key=durable_key,
                    status=terminal_status,
                    transmission_status=transmission,  # type: ignore[arg-type]
                    candidate_count=len(response.hits),
                    known_count=response.known_count,
                    unknown_count=max(0, response.result_count - response.known_count),
                    rejected_count=0,
                    duration_ms=response.duration_ms,
                    error_code=error_code,
                    completed_at=datetime.now(UTC),
                )
                _finalize(
                    self.quota_adapter,
                    reservation_id=reservation_id,
                    terminal=terminal,
                )
                try:
                    _commit_boundary(self.quota_adapter)
                except Exception as exc:
                    raise RuntimeError("transmission_indeterminate") from exc
                responses.append((query.ordinal, response))
                if response.status == "indeterminate":
                    self.last_responses = tuple(responses)
                    raise RuntimeError("transmission_indeterminate")
            if response is not None:
                continue
        self.last_responses = tuple(responses)
        hits = [
            BoardSearchHitV2(query_ordinal, response.provider, hit.rank, hit.url)
            for query_ordinal, response in responses
            for hit in response.hits
        ]
        classified = classify_board_candidates(hits)
        unique_candidates: list[BoardCandidateV2] = []
        seen_source_keys: set[str] = set()
        for candidate in classified:
            if candidate.source_key in seen_source_keys:
                continue
            seen_source_keys.add(candidate.source_key)
            unique_candidates.append(
                BoardCandidateV2(
                    source_type=candidate.source_type,
                    source_key=candidate.source_key,
                    configuration=candidate.configuration,
                    canonical_url=candidate.canonical_url,
                    query_ordinal=candidate.query_ordinal,
                    provider=candidate.provider,
                    rank=candidate.rank,
                    ordinal=len(unique_candidates) + 1,
                )
            )
        self.unique_board_candidates_seen = len(unique_candidates)
        self.candidate_truncated = len(unique_candidates) > 10
        candidates = tuple(unique_candidates[:10])
        for _candidate in candidates:
            budget.reserve_candidate()
        self.execution_budget = budget
        self.last_status = (
            "succeeded"
            if any(response.status in {"succeeded", "empty"} for _, response in responses)
            else "failed"
            if responses
            else "empty"
        )
        return candidates

    async def candidates_async(self) -> tuple[BoardCandidateV2, ...]:
        return await self.search()


BoundedSearchRuntimeV2 = BoundedSearchRuntime


@dataclass(slots=True)
class OfficialATSVerifier:
    """Verify only classified official ATS boards through a bounded collector."""

    collector_provider: BoundedCollectorProvider

    async def __call__(self, candidate: DiscoveryCandidate) -> VerifiedSource | None:
        classified = classify_url(candidate.url)
        if isinstance(classified, GreenhouseOfficialCandidate):
            source_type = "greenhouse"
            configuration = dict(classified.configuration)
            name = f"Greenhouse {classified.board_token}"
        elif isinstance(classified, LeverOfficialCandidate):
            source_type = "lever"
            configuration = dict(classified.configuration)
            name = f"Lever {classified.site}"
        else:
            return None
        source_key = canonical_source_key(source_type, configuration)
        snapshot = SourceSnapshot(
            source_id=f"discovery:{source_key}",
            source_key=source_key,
            source_type=source_type,
            name=name,
            configuration=configuration,
            revision=1,
        )
        outcome = await self.collector_provider(snapshot)
        if isinstance(outcome, CollectionSuccess):
            # Empty is a valid, structurally verified board.  Jobs are not
            # persisted here; only the count crosses into registration.
            return VerifiedSource(
                source_key,
                "greenhouse" if source_type == "greenhouse" else "lever",
                name,
                configuration,
                len(outcome.jobs),
            )
        return None


@dataclass(slots=True)
class ReportOnlyATSVerifier:
    """Report-only adapter over the existing source-only ATS collectors."""

    collector_provider: BoundedCollectorProvider
    operation_sha256: str | None = None
    wire_budget: CollectionRunBudget = field(default_factory=CollectionRunBudget)
    before_transport_check: Callable[[], None] | None = None

    def __post_init__(self) -> None:
        self.collector_provider.set_budget(self.wire_budget)

    @property
    def wire_attempts_consumed(self) -> int:
        return self.wire_budget.consumed

    async def __call__(self, candidate: BoardCandidateV2) -> ReportOnlyVerifiedSourceV1 | None:
        if candidate.source_type not in {"greenhouse", "lever"}:
            return None
        configuration = dict(candidate.configuration)
        name = f"{candidate.source_type}:{candidate.source_key}"
        snapshot = SourceSnapshot(
            source_id=f"discovery:{candidate.source_key}",
            source_key=candidate.source_key,
            source_type=candidate.source_type,
            name=name,
            configuration=configuration,
            revision=1,
        )
        outcome = await self.collector_provider(snapshot)
        if not isinstance(outcome, CollectionSuccess):
            return None
        request_identity = "0" * 64
        if self.operation_sha256 is not None:
            request_identity = sha256(
                canonical_json_bytes(
                    {
                        "operation_sha256": self.operation_sha256,
                        "source_type": candidate.source_type,
                        "source_key": candidate.source_key,
                        "configuration_sha256": sha256(
                            canonical_json_bytes(configuration)
                        ).hexdigest(),
                        "destination": (
                            "greenhouse_official_api"
                            if candidate.source_type == "greenhouse"
                            else "lever_eu_official_api"
                            if configuration.get("region") == "eu"
                            else "lever_global_official_api"
                        ),
                        "board_candidate_ordinal": candidate.ordinal,
                        "wire_attempt_ordinal": 1,
                        "collector_request_ordinal": 1,
                    }
                )
            ).hexdigest()
        return ReportOnlyVerifiedSourceV1(
            source_type=candidate.source_type,
            source_key=candidate.source_key,
            configuration=configuration,
            configuration_sha256=sha256(canonical_json_bytes(configuration)).hexdigest(),
            postings_count=len(outcome.jobs),
            board_candidate_ordinal=candidate.ordinal,
            request_identity_sha256=request_identity,
        )


def create_bounded_collector_provider(
    *,
    transport: object | None = None,
    clock: Callable[[], float] | None = None,
    sleeper: Callable[[float], Awaitable[None]] | None = None,
    user_agent: str = "role-radar/0.1 (+homelab)",
    collector_factory: Callable[
        [CollectorSnapshot, CollectorContext], JobCollector
    ] = create_collector,
) -> BoundedCollectorProvider:
    """Build the registry-backed collector seam without touching the network."""

    return BoundedCollectorProvider(
        transport=transport,
        clock=clock,
        sleeper=sleeper,
        user_agent=user_agent,
        collector_factory=collector_factory,
    )


def create_official_ats_verifier(
    collector_provider: BoundedCollectorProvider,
) -> OfficialATSVerifier:
    """Build the source-only verifier used by continuous discovery."""

    return OfficialATSVerifier(collector_provider)


# Compatibility fakes remain intentionally synchronous for existing offline tests.
@dataclass(frozen=True, slots=True)
class FakeSearchProvider:
    hits: tuple[DiscoveryCandidate, ...] = ()

    def candidates(self) -> tuple[DiscoveryCandidate, ...]:
        return self.hits


@dataclass(frozen=True, slots=True)
class FakeBoardVerifier:
    boards: tuple[VerifiedSource, ...] = ()

    def __call__(self, candidate: DiscoveryCandidate) -> VerifiedSource | None:
        return next((board for board in self.boards if board.source_key in candidate.url), None)
