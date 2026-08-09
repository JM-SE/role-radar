"""Immutable, ORM-free contracts for discovery planning and execution."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from role_radar.collectors.outcomes import CollectionOutcome
from role_radar.collectors.protocols import SourceSnapshot
from role_radar.domain.dto import RawJob


class ProviderIntent(StrEnum):
    EXACT = "exact"
    SEMANTIC = "semantic"


@dataclass(frozen=True, slots=True)
class PlannedQuery:
    ordinal: int
    family: str
    provider_intent: ProviderIntent
    canonical_query: str


@dataclass(frozen=True, slots=True)
class QueryIdentity:
    ordinal: int
    family: str
    provider_intent: ProviderIntent
    query_key: str


@dataclass(frozen=True, slots=True)
class DiscoveryPlan:
    run_id: str
    cycle_id: str
    profile_snapshot: Mapping[str, object]
    queries: tuple[PlannedQuery, ...]
    identities: tuple[QueryIdentity, ...]
    planner_version: str
    planner_hash: str
    policy_version: str
    reused: bool = False
    reused_job_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GreenhouseOfficialCandidate:
    canonical_url: str
    board_token: str
    job_path: str | None = None

    @property
    def source_type(self) -> Literal["greenhouse"]:
        return "greenhouse"

    @property
    def configuration(self) -> Mapping[str, str]:
        return {"board_token": self.board_token}


@dataclass(frozen=True, slots=True)
class LeverOfficialCandidate:
    canonical_url: str
    site: str
    region: Literal["global", "eu"]
    posting_id: str | None = None

    @property
    def source_type(self) -> Literal["lever"]:
        return "lever"

    @property
    def configuration(self) -> Mapping[str, str]:
        return {"site": self.site, "region": self.region}


@dataclass(frozen=True, slots=True)
class UnknownCandidate:
    reason: str


@dataclass(frozen=True, slots=True)
class RejectedCandidate:
    reason: str


KnownOfficialCandidate = GreenhouseOfficialCandidate | LeverOfficialCandidate
ClassifiedCandidate = KnownOfficialCandidate | UnknownCandidate | RejectedCandidate


@dataclass(frozen=True, slots=True)
class QueryExecution:
    identity: QueryIdentity
    status: str
    candidate_count: int
    known_count: int
    unknown_count: int
    rejected_count: int
    verified_count: int


@dataclass(frozen=True, slots=True)
class VerifiedBatch:
    candidate: KnownOfficialCandidate
    snapshot: SourceSnapshot
    outcome: CollectionOutcome
    jobs: tuple[RawJob, ...]


@dataclass(frozen=True, slots=True)
class DiscoveryExecution:
    plan: DiscoveryPlan
    queries: tuple[QueryExecution, ...]
    verified_batches: tuple[VerifiedBatch, ...]
    error_code: str | None = None
    reused_job_ids: tuple[str, ...] = ()

    @property
    def producer_success(self) -> bool:
        return bool(self.verified_batches or self.reused_job_ids)


@dataclass(frozen=True, slots=True)
class DiscoveryFinalization:
    cycle_id: str
    verified_sources: int
    verified_jobs: int
    blocked_candidates: int
    producer_success: bool
    status: str


@dataclass(frozen=True, slots=True)
class SourceRegistration:
    source_id: str | None
    source_key: str
    created: bool
    linked: bool
    blocked: bool
