"""Versioned, I/O-free contracts for continuous acquisition."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, Protocol

from role_radar.collectors.outcomes import CollectionOutcome
from role_radar.domain.dto import RawJob

ACQUISITION_POLICY_VERSION = "continuous-acquisition-v1"
FRESHNESS_POLICY_VERSION = "freshness-14d-v1"
IDENTITY_POLICY_VERSION = "strong-identity-v1"
DISCOVERY_POLICY_VERSION = "source-discovery-v1"
SLOT_VERSION = "daily-slot-v1"


class AcquisitionRunState(StrEnum):
    COMPLETED = "completed"
    COMPLETED_EMPTY = "completed_empty"
    COMPLETED_PARTIAL = "completed_partial"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class OperationState(StrEnum):
    INTENT = "intent"
    SUCCEEDED = "succeeded"
    EMPTY = "empty"
    FAILED = "failed"
    TRUNCATED = "truncated"
    INDETERMINATE = "indeterminate"


class DiscoveryRunState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"


class OfferDisposition(StrEnum):
    CREATED = "created"
    DUPLICATE = "duplicate"


class RejectionCode(StrEnum):
    MISSING_RECENCY = "freshness_timestamp_missing"
    INVALID_RECENCY = "freshness_timestamp_invalid"
    STALE = "freshness_before_cutoff"
    FUTURE = "freshness_future"
    CLOSED = "provider_closed"
    EXPIRED = "expired_at_selection_time"
    INVALID = "invalid_offer"
    IDENTITY_CONFLICT = "identity_conflict"


@dataclass(frozen=True, slots=True)
class RecencyProvenance:
    provider_recency_at: datetime
    semantic: str
    policy_version: str = FRESHNESS_POLICY_VERSION

    def __post_init__(self) -> None:
        if self.provider_recency_at.tzinfo is None or self.provider_recency_at.utcoffset() is None:
            raise ValueError("provider recency must be timezone-aware")


@dataclass(frozen=True, slots=True)
class FreshnessDecision:
    accepted: bool
    code: str | None
    provenance: RecencyProvenance | None
    cutoff_utc: datetime


@dataclass(frozen=True, slots=True)
class JobCounters:
    observed: int = 0
    created: int = 0
    duplicate: int = 0
    stale: int = 0
    invalid: int = 0
    conflict: int = 0

    def __post_init__(self) -> None:
        if min(
            self.observed, self.created, self.duplicate, self.stale, self.invalid, self.conflict
        ) < 0:
            raise ValueError("counters must be nonnegative")

    @property
    def classified(self) -> int:
        return self.created + self.duplicate + self.stale + self.invalid + self.conflict

    def conserved(self) -> bool:
        return self.observed == self.classified

    def add(self, other: JobCounters) -> JobCounters:
        return JobCounters(
            self.observed + other.observed,
            self.created + other.created,
            self.duplicate + other.duplicate,
            self.stale + other.stale,
            self.invalid + other.invalid,
            self.conflict + other.conflict,
        )


@dataclass(frozen=True, slots=True)
class Budget:
    discovery_brave_queries: int = 4
    discovery_tavily_queries: int = 4
    discovery_hits_per_query: int = 10
    new_sources_per_run: int = 8
    active_discovery_sources: int = 50
    acquisition_wire_requests: int = 100
    run_deadline_minutes: int = 20
    version: str = ACQUISITION_POLICY_VERSION


@dataclass(frozen=True, slots=True)
class BudgetCounter:
    reserved: int = 0
    attempted: int = 0
    completed: int = 0
    truncated: int = 0

    def reserve(self, amount: int, limit: int) -> BudgetCounter:
        if amount < 0 or self.reserved + amount > limit:
            raise ValueError("budget reservation exceeds limit")
        return BudgetCounter(self.reserved + amount, self.attempted, self.completed, self.truncated)

    def attempted_once(self) -> BudgetCounter:
        if self.attempted >= self.reserved:
            raise ValueError("attempt must be reserved first")
        return BudgetCounter(self.reserved, self.attempted + 1, self.completed, self.truncated)

    def completed_once(self) -> BudgetCounter:
        if self.completed >= self.attempted:
            raise ValueError("completion must follow an attempt")
        return BudgetCounter(self.reserved, self.attempted, self.completed + 1, self.truncated)

    def truncate(self) -> BudgetCounter:
        return BudgetCounter(self.reserved, self.attempted, self.completed, self.truncated + 1)


class RequestBudget:
    """Deterministic runtime budget shared by all requests in one run.

    The clock is injected so collectors and tests can use this without sleeping
    or consulting wall-clock time.  ``prefix`` deliberately returns only the
    items already admitted; callers can persist its continuation token.
    """

    def __init__(
        self,
        *,
        maximum: int = 100,
        deadline: timedelta = timedelta(minutes=20),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if maximum < 0 or deadline.total_seconds() < 0:
            raise ValueError("invalid request budget")
        self.maximum = maximum
        self.deadline = deadline
        self._clock = clock or (lambda: datetime.now(UTC))
        self.started_at = self._clock()
        self.counter = BudgetCounter()

    @property
    def exhausted(self) -> bool:
        return self.counter.reserved >= self.maximum or self._clock() >= self.started_at + self.deadline

    def reserve(self, amount: int = 1) -> bool:
        if amount < 0 or self.exhausted or self.counter.reserved + amount > self.maximum:
            return False
        self.counter = self.counter.reserve(amount, self.maximum)
        return True

    def begin_attempt(self) -> bool:
        if (
            self._clock() >= self.started_at + self.deadline
            or self.counter.attempted >= self.counter.reserved
        ):
            return False
        self.counter = self.counter.attempted_once()
        return True

    def complete(self) -> None:
        self.counter = self.counter.completed_once()

    def truncate(self, items: tuple[Any, ...], *, continuation: str | None = None) -> tuple[tuple[Any, ...], str | None]:
        self.counter = self.counter.truncate()
        return items[: self.counter.completed], continuation


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    source_id: str
    source_key: str
    source_type: str
    name: str
    configuration: Mapping[str, Any]
    revision: int = 1


@dataclass(frozen=True, slots=True)
class AcquisitionSourceOutcome:
    source_id: str
    state: OperationState
    counters: JobCounters = field(default_factory=JobCounters)
    usable: bool = False
    error_code: str | None = None
    continuation: str | None = None


@dataclass(frozen=True, slots=True)
class AcquisitionRunResult:
    state: AcquisitionRunState
    new_jobs: int
    outcomes: tuple[AcquisitionSourceOutcome, ...]
    counters: JobCounters = field(default_factory=JobCounters)
    terminal_code: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    url: str
    provider: str
    rank: int


@dataclass(frozen=True, slots=True)
class VerifiedSource:
    source_key: str
    source_type: Literal["greenhouse", "lever"]
    name: str
    configuration: Mapping[str, Any]
    postings: int


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    source_id: str | None
    disposition: str
    source_key: str
    state_evidence: str


class SourceCollector(Protocol):
    def __call__(
        self, source: SourceSnapshot
    ) -> CollectionOutcome | Awaitable[CollectionOutcome] | tuple[RawJob, ...]: ...


class BoardVerifier(Protocol):
    def __call__(self, candidate: DiscoveryCandidate) -> VerifiedSource | None: ...
