"""Injected bounded provider runtimes for the continuous source-only path.

This module intentionally contains adapters, not an alternative collector or
search implementation.  Network policy remains owned by the existing bounded
Greenhouse/Lever and Brave/Tavily adapters.  The objects below only translate
the continuous-context DTOs and discard provider payloads after each call.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

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
from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    LeverOfficialCandidate,
    PlannedQuery,
    ProviderIntent,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
)
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.discovery.url_classifier import classify_url
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


DISCOVERY_HOSTS = (
    "boards.greenhouse.io",
    "job-boards.greenhouse.io",
    "jobs.lever.co",
    "jobs.eu.lever.co",
)
DISCOVERY_ROLES = (
    "Senior Frontend",
    "Frontend Architect",
    "Staff Frontend",
    "Senior Full-stack",
)
MAX_DISCOVERY_QUERIES = 4
MAX_DISCOVERY_HITS = 10


def _broad_queries() -> tuple[PlannedQuery, ...]:
    roles = " OR ".join(f'"{role}"' for role in DISCOVERY_ROLES)
    return tuple(
        PlannedQuery(index, f"ats_host:{host}", ProviderIntent.EXACT, f"site:{host} ({roles})")
        for index, host in enumerate(DISCOVERY_HOSTS, start=1)
    )


@dataclass(slots=True)
class BoundedSearchRuntime:
    """Transient Brave-first discovery with Tavily fallback.

    ``run`` returns only URL/rank candidates.  Plaintext queries and provider
    response bodies remain local to this object and are never sent to a store.
    """

    brave: SearchProvider | None = None
    tavily: SearchProvider | None = None
    query_secret: bytes | str = b"offline-test-query-key"
    planner_version: str = "continuous-discovery-v1"
    query_version: str = "continuous-discovery-v1"
    queries: tuple[PlannedQuery, ...] = field(default_factory=_broad_queries)
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
