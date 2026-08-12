"""Pure F10.1 data contracts; no network, ORM, or filesystem imports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class OperationState(StrEnum):
    PLANNED = "planned"
    PLAN_APPROVED = "plan_approved"
    ACQUIRING = "acquiring"
    POOL_SEALED = "pool_sealed"
    SELECTED = "selected"
    STAGED = "staged"
    VERIFIED = "verified"
    PUBLISHED = "published"
    COMPLETED = "completed"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"
    ABORTED = "aborted"


class SourceFamily(StrEnum):
    JOBICY = "jobicy"
    GREENHOUSE = "greenhouse"
    LEVER = "lever"


@dataclass(frozen=True, slots=True)
class Observation:
    source_family: str
    source_id: str
    source_key: str
    source_revision: int
    configuration_version: int
    external_id: str
    title: str
    company: str
    location: str | None
    description: str | None
    source_url: str | None
    application_url: str | None
    provider_recency_at: datetime | None
    recency_semantic: str | None
    provider_status: str | None
    expires_at: datetime | None
    collected_at: datetime
    official_listing: bool = True
    provider_payload_sha256: str | None = None
    structured_data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HistoricalIdentity:
    source_family: str
    source_key: str
    external_id: str | None
    official_url: str | None
    application_url: str | None
    company_title_location_key: str | None = None
    description_hash: str | None = None


@dataclass(frozen=True, slots=True)
class Exclusion:
    identity: str
    reason: str


@dataclass(frozen=True, slots=True)
class CandidateCluster:
    cluster_id: str
    observations: tuple[Observation, ...]
    strong_keys: tuple[str, ...]
    weak_conflict: bool = False

    @property
    def families(self) -> frozenset[str]:
        return frozenset(item.source_family for item in self.observations)

    @property
    def primary(self) -> Observation:
        return sorted(
            self.observations,
            key=lambda item: (item.source_family, item.source_key, item.external_id),
        )[0]


@dataclass(frozen=True, slots=True)
class SelectedCandidate:
    cluster: CandidateCluster
    selection_family: str
    selection_reason: str


@dataclass(frozen=True, slots=True)
class DatasetResult:
    status: str
    selected: tuple[SelectedCandidate, ...]
    target_counts: Mapping[str, int]
    actual_counts: Mapping[str, int]
    deficit_counts: Mapping[str, int]
    fallback_count: int
    exclusions: tuple[Exclusion, ...] = ()


@dataclass(frozen=True, slots=True)
class OperationPlan:
    plan_version: str
    profile_sha256: str
    selection_as_of_utc: datetime
    cutoff_utc: datetime
    lookback_days: int
    source_configs: tuple[Mapping[str, Any], ...]
    wire_attempt_cap: int = 100
    query_template_hashes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceCheckpoint:
    source_id: str
    source_type: str
    source_key: str
    name: str
    revision: int
    configuration_version: int
    configuration: Mapping[str, Any]
    enabled: bool
    archived: bool


@dataclass(frozen=True, slots=True)
class LiveRunResult:
    operation_id: str
    state: OperationState
    observations: tuple[Observation, ...] = ()
    dataset_result: DatasetResult | None = None
    error_code: str | None = None
    dataset_id: str | None = None


@dataclass(frozen=True, slots=True)
class DatasetItem:
    ordinal: int
    opaque_id: str
    title: str
    company: str
    location: str | None
    description: str | None
    source_url: str | None
    application_url: str | None
    provider_recency_at: datetime | None
    recency_semantic: str | None
    selection_family: str
    selection_reason: str
