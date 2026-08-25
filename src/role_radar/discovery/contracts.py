"""Immutable, ORM-free contracts for discovery planning and execution."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from role_radar.collectors.outcomes import CollectionOutcome
from role_radar.collectors.protocols import SourceSnapshot
from role_radar.domain.dto import RawJob


class ProviderIntent(StrEnum):
    EXACT = "exact"
    SEMANTIC = "semantic"


class ProviderTier(StrEnum):
    FREE = "free"
    PAID = "paid"


class SearchRequest(BaseModel):
    """Transient provider-neutral request.

    ``query`` is deliberately excluded from repr so accidental structured logs
    cannot disclose the plaintext query.  The request is only constructed in
    the worker immediately before an adapter call.
    """

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    operation_key: str = Field(min_length=1, max_length=512)
    query: str = Field(min_length=1, max_length=2048, repr=False)
    query_key: str = Field(min_length=1, max_length=128)
    planner_version: str = Field(min_length=1, max_length=64)
    query_version: str = Field(min_length=1, max_length=64)
    max_results: int = Field(default=10, gt=0, le=10)
    deadline_seconds: float = Field(default=20.0, gt=0, le=20.0)
    provider_intent: ProviderIntent
    cycle_query_count: int = Field(default=1, ge=1, le=24)

    @field_validator("query")
    @classmethod
    def query_has_no_controls(cls, value: str) -> str:
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("query contains control characters")
        if re.search(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", value):
            raise ValueError("query contains an email address")
        return value


class TransientSearchHit(BaseModel):
    """A bounded URL/rank pair; it must never cross a persistence boundary."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    url: str = Field(min_length=1, max_length=2048, repr=False)
    rank: int = Field(gt=0, le=10)


class SearchResponse(BaseModel):
    """Sanitized provider outcome.  Provider payloads are discarded by adapters."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    provider: Literal["brave", "tavily"]
    tier: ProviderTier
    status: Literal["succeeded", "empty", "failed", "malformed", "indeterminate"]
    hits: tuple[TransientSearchHit, ...] = ()
    result_count: int = Field(default=0, ge=0, le=10)
    known_count: int = Field(default=0, ge=0, le=10)
    duration_ms: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, max_length=64)

    @field_validator("hits")
    @classmethod
    def bound_hits(cls, value: tuple[TransientSearchHit, ...]) -> tuple[TransientSearchHit, ...]:
        if len(value) > 10:
            raise ValueError("too many search hits")
        return value


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
