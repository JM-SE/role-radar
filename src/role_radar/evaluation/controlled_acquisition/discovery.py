"""Bounded discovery-first policy for F10.1.

This module contains no ORM or product-pipeline integration.  Search providers
return transient URLs; an injected verifier is the only seam allowed to turn a
classified URL into an ephemeral, verified collector configuration.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from role_radar.collectors.outcomes import CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext, create_collector
from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    KnownOfficialCandidate,
    LeverOfficialCandidate,
    PlannedQuery,
    ProviderIntent,
    SearchRequest,
    SearchResponse,
)
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.discovery.url_classifier import classify_url
from role_radar.evaluation.controlled_acquisition.acquisition import (
    JournaledTransport,
    observation_from_raw,
)
from role_radar.evaluation.controlled_acquisition.protocols import (
    ALLOWED_ORIGINS,
    BASELINE_PROFILE_ID,
    BASELINE_PROFILE_SCHEMA_VERSION,
    BASELINE_PROFILE_VERSION,
    DISCOVERY_QUERY_TEMPLATE_VERSION,
    DISCOVERY_VERIFICATION_VERSION,
    PLAN_VERSION_V2,
    PROTOCOL_VERSION,
)
from role_radar.evaluation.controlled_acquisition.recency import eligibility
from role_radar.evaluation.controlled_acquisition.source_plan import (
    SourcePlan,
    canonical_sha256,
    load_plan,
)
from role_radar.sources.identity import canonical_source_key

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
DISCOVERY_CONFIRMATION = "I ACKNOWLEDGE F10.1 LIVE DISCOVERY REPORT ONLY"


class DiscoverySearchProvider(Protocol):
    @property
    def provider(self) -> str: ...

    async def search(self, request: SearchRequest) -> SearchResponse: ...

    async def aclose(self) -> None: ...


class LazyDiscoverySearchProvider:
    """Create a fallback provider only when its first query is required."""

    def __init__(self, factory: Callable[[], DiscoverySearchProvider], *, provider: str) -> None:
        self._factory = factory
        self._provider = provider
        self._delegate: DiscoverySearchProvider | None = None

    @property
    def provider(self) -> str:
        return self._provider

    async def search(self, request: SearchRequest) -> SearchResponse:
        if self._delegate is None:
            candidate = self._factory()
            enter = getattr(candidate, "__aenter__", None)
            self._delegate = await enter() if enter is not None else candidate
        return await self._delegate.search(request)

    async def aclose(self) -> None:
        if self._delegate is not None:
            await self._delegate.aclose()
            self._delegate = None


@dataclass(frozen=True, slots=True)
class VerifiedEphemeralConfig:
    candidate: KnownOfficialCandidate
    eligible_count: int
    source_key: str
    configuration: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class DiscoveryQueryReport:
    provider: str
    ordinal: int
    status: str
    hit_count: int
    known_count: int
    rejected_count: int
    verified_count: int


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    planner_version: str
    verification_version: str
    query_count: int
    verified_configs: tuple[VerifiedEphemeralConfig, ...]
    query_reports: tuple[DiscoveryQueryReport, ...]
    fallback_used: bool

    def private_dict(self) -> dict[str, object]:
        return {
            "planner_version": self.planner_version,
            "verification_version": self.verification_version,
            "query_count": self.query_count,
            "fallback_used": self.fallback_used,
            "verified_configs": [
                {
                    "family": item.candidate.source_type,
                    "source_key": item.source_key,
                    "configuration": dict(item.configuration),
                    "eligible_count": item.eligible_count,
                }
                for item in self.verified_configs
            ],
            "query_reports": [
                {
                    "provider": item.provider,
                    "ordinal": item.ordinal,
                    "status": item.status,
                    "hit_count": item.hit_count,
                    "known_count": item.known_count,
                    "rejected_count": item.rejected_count,
                    "verified_count": item.verified_count,
                }
                for item in self.query_reports
            ],
        }

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "schema_version": "f10.1-discovery-report-v1",
            "planner_version": self.planner_version,
            "verification_version": self.verification_version,
            "query_count": self.query_count,
            "verified_config_count": len(self.verified_configs),
            "eligible_count": sum(item.eligible_count for item in self.verified_configs),
            "fallback_used": self.fallback_used,
            "providers": {
                provider: sum(1 for item in self.query_reports if item.provider == provider)
                for provider in ("brave", "tavily")
            },
        }


class DiscoveryQueryPlanner:
    version = DISCOVERY_QUERY_TEMPLATE_VERSION

    def plan(self) -> tuple[PlannedQuery, ...]:
        terms = " OR ".join(f'"{role}"' for role in DISCOVERY_ROLES)
        return tuple(
            PlannedQuery(
                ordinal=index,
                family=f"ats_host:{host}",
                provider_intent=ProviderIntent.EXACT,
                canonical_query=f"site:{host} ({terms})",
            )
            for index, host in enumerate(DISCOVERY_HOSTS)
        )


Verifier = Callable[
    [KnownOfficialCandidate, datetime], Awaitable[VerifiedEphemeralConfig | None]
]


@dataclass(frozen=True, slots=True)
class OfficialBoardVerifier:
    """Verify a classified board using only its fixed official collector API."""

    context: CollectorContext | None = None
    wire_attempt_cap: int = 100
    journal: Any | None = None

    async def __call__(
        self, candidate: KnownOfficialCandidate, selection_as_of_utc: datetime
    ) -> VerifiedEphemeralConfig | None:
        configuration = dict(candidate.configuration)
        source_key = canonical_source_key(candidate.source_type, configuration)
        source_id = f"ephemeral:{hashlib.sha256(source_key.encode()).hexdigest()[:32]}"
        snapshot = SourceSnapshot(
            source_id=source_id,
            source_type=candidate.source_type,
            name=source_key,
            configuration=configuration,
            source_key=source_key,
            configuration_version=1,
        )
        base_context = self.context or CollectorContext()
        transport = base_context.transport
        if self.journal is not None:
            transport = JournaledTransport(
                operation_id=(
                    f"f10.1-ats-verify:{source_key}:"
                    f"{selection_as_of_utc.astimezone(UTC).replace(microsecond=0).isoformat()}"
                ),
                source_id=source_id,
                journal=self.journal,
                transport=transport,
            )
        collector = create_collector(
            snapshot,
            CollectorContext(
                transport=transport,
                clock=base_context.clock,
                sleeper=base_context.sleeper,
                budget=base_context.budget,
                user_agent=base_context.user_agent,
            ),
        )
        outcome = await collector.collect(
            snapshot,
            CollectorRuntime(budget=CollectionRunBudget(self.wire_attempt_cap)),
        )
        if not isinstance(outcome, CollectionSuccess):
            return None
        eligible_count = 0
        for raw in outcome.jobs:
            observation = observation_from_raw(
                raw,
                source_id=source_id,
                source_key=source_key,
                source_revision=0,
                configuration_version=1,
            )
            if eligibility(
                observation,
                cutoff_utc=selection_as_of_utc.astimezone(UTC).replace(microsecond=0)
                - timedelta(days=14),
                as_of_utc=selection_as_of_utc,
            ) is None:
                eligible_count += 1
        if eligible_count < 1:
            return None
        return VerifiedEphemeralConfig(
            candidate=candidate,
            eligible_count=eligible_count,
            source_key=source_key,
            configuration=configuration,
        )


class DiscoveryOrchestrator:
    """Run at most four primary and four fallback searches, with no retries."""

    def __init__(
        self,
        *,
        query_hmac: bytes | str,
        verifier: Verifier,
        planner: DiscoveryQueryPlanner | None = None,
        journal: Any | None = None,
    ) -> None:
        self._keys = QueryKeyFactory(query_hmac)
        self._verifier = verifier
        self._planner = planner or DiscoveryQueryPlanner()
        self._journal = journal

    async def run(
        self,
        *,
        brave: DiscoverySearchProvider,
        tavily: DiscoverySearchProvider,
        selection_as_of_utc: datetime,
        profile_sha256: str,
        profile_id: str,
        profile_version: int,
        profile_schema_version: int,
        source_commit: str,
        source_diff_sha256: str,
        source_status_sha256: str,
        alembic_head: str,
        jobicy: Mapping[str, object] | None = None,
    ) -> tuple[DiscoveryReport, SourcePlan]:
        if (
            profile_id != BASELINE_PROFILE_ID
            or profile_version != BASELINE_PROFILE_VERSION
            or profile_schema_version != BASELINE_PROFILE_SCHEMA_VERSION
        ):
            raise ValueError("profile_baseline_mismatch")
        queries = self._planner.plan()
        primary, primary_reports = await self._search_and_verify(
            brave, queries, selection_as_of_utc
        )
        fallback_used = sum(item.eligible_count for item in primary) < 50
        fallback: tuple[VerifiedEphemeralConfig, ...] = ()
        fallback_reports: tuple[DiscoveryQueryReport, ...] = ()
        if fallback_used:
            fallback, fallback_reports = await self._search_and_verify(
                tavily, queries, selection_as_of_utc
            )
        configs = _deduplicate_configs((*primary, *fallback))
        report = DiscoveryReport(
            planner_version=self._planner.version,
            verification_version=DISCOVERY_VERIFICATION_VERSION,
            query_count=len(primary_reports) + len(fallback_reports),
            verified_configs=configs,
            query_reports=primary_reports + fallback_reports,
            fallback_used=fallback_used,
        )
        as_of = selection_as_of_utc.astimezone(UTC).replace(microsecond=0)
        cutoff = as_of - timedelta(days=14)
        source_configs = [
            {
                "family": item.candidate.source_type,
                "source_key": item.source_key,
                "configuration_version": 1,
                "configuration": dict(item.configuration),
                "verification": {
                    "policy_version": DISCOVERY_VERIFICATION_VERSION,
                    "eligible_count": item.eligible_count,
                },
            }
            for item in configs
        ]
        if jobicy is not None:
            source_configs.append(dict(jobicy))
        source_configs.sort(key=lambda item: (str(item["family"]), str(item["source_key"])))
        report_hash = canonical_sha256(report.private_dict())
        plan = SourcePlan(
            PLAN_VERSION_V2,
            14,
            tuple(source_configs),
            query_template_hashes=tuple(
                canonical_sha256(query.canonical_query) for query in queries
            ),
            allowed_origins=ALLOWED_ORIGINS,
            profile_sha256=profile_sha256,
            profile_id=profile_id,
            profile_version=profile_version,
            profile_schema_version=profile_schema_version,
            selection_as_of_utc=as_of.isoformat().replace("+00:00", "Z"),
            source_commit=source_commit,
            source_diff_sha256=source_diff_sha256,
            source_status_sha256=source_status_sha256,
            alembic_head=alembic_head,
            protocol_version=PROTOCOL_VERSION,
            query_planner_version=self._planner.version,
            verification_policy_version=DISCOVERY_VERIFICATION_VERSION,
            discovery_report_sha256=report_hash,
            cutoff_utc=cutoff.isoformat().replace("+00:00", "Z"),
        )
        return report, load_plan(plan.as_dict())

    async def _search_and_verify(
        self,
        provider: DiscoverySearchProvider,
        queries: Sequence[PlannedQuery],
        as_of: datetime,
    ) -> tuple[tuple[VerifiedEphemeralConfig, ...], tuple[DiscoveryQueryReport, ...]]:
        configs: list[VerifiedEphemeralConfig] = []
        reports: list[DiscoveryQueryReport] = []
        for query in queries[:MAX_DISCOVERY_QUERIES]:
            operation_id = (
                f"f10.1-discovery:{provider.provider}:{query.ordinal}:"
                f"{as_of.astimezone(UTC).replace(microsecond=0).isoformat()}"
            )
            if self._journal is not None and self._journal.has_pending_request(operation_id):
                raise ValueError("discovery_request_indeterminate")
            request = SearchRequest(
                operation_key=operation_id,
                query=query.canonical_query,
                query_key=self._keys.key(query, planner_version=self._planner.version),
                planner_version=self._planner.version,
                query_version=self._planner.version,
                max_results=MAX_DISCOVERY_HITS,
                provider_intent=query.provider_intent,
                cycle_query_count=len(queries),
            )
            request_id = hashlib.sha256(
                f"{operation_id}:{request.query_key}".encode("ascii")
            ).hexdigest()
            self._record_request_intent(operation_id, request_id)
            response = await provider.search(request)
            self._record_request_result(operation_id, request_id)
            known = rejected = verified = 0
            for hit in response.hits[:MAX_DISCOVERY_HITS]:
                candidate = classify_url(hit.url)
                if isinstance(candidate, (GreenhouseOfficialCandidate, LeverOfficialCandidate)):
                    known += 1
                    checked = await self._verifier(candidate, as_of)
                    if checked is not None:
                        configs.append(checked)
                        verified += 1
                else:
                    rejected += 1
            reports.append(
                DiscoveryQueryReport(
                    provider=provider.provider,
                    ordinal=query.ordinal,
                    status=response.status,
                    hit_count=len(response.hits),
                    known_count=known,
                    rejected_count=rejected,
                    verified_count=verified,
                )
            )
        return tuple(configs), tuple(reports)

    def _record_request_intent(self, operation_id: str, request_id: str) -> None:
        if self._journal is not None:
            self._journal.record_request_intent(operation_id=operation_id, request_id=request_id)

    def _record_request_result(self, operation_id: str, request_id: str) -> None:
        if self._journal is not None:
            self._journal.record_request_result(operation_id=operation_id, request_id=request_id)


def _deduplicate_configs(
    configs: Sequence[VerifiedEphemeralConfig],
) -> tuple[VerifiedEphemeralConfig, ...]:
    by_key: dict[str, VerifiedEphemeralConfig] = {}
    for config in configs:
        by_key.setdefault(config.source_key, config)
    return tuple(by_key[key] for key in sorted(by_key))


def require_discovery_confirmation(value: str) -> None:
    if value != DISCOVERY_CONFIRMATION:
        raise ValueError("discovery_confirmation_required")


def write_discovery_artifacts(root: str, report: DiscoveryReport, plan: SourcePlan) -> None:
    """Write only protected report/plan JSON; never writes product DB state."""
    path = os.path.abspath(root)
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    payloads = {
        "discovery-report.json": report.private_dict(),
        "source-plan-v2.json": plan.as_dict(),
    }
    for name, value in payloads.items():
        target = os.path.join(path, name)
        if os.path.islink(target):
            raise ValueError("discovery_artifact_symlink")
        if os.path.exists(target):
            raise ValueError("discovery_artifact_exists")
        temporary = f"{target}.tmp"
        data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with open(temporary, "x", encoding="utf-8") as stream:
            stream.write(data)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    directory_fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
