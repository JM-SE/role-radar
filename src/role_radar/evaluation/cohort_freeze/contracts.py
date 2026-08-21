"""Immutable, IO-free contracts for F10.1C."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class CohortStatus(StrEnum):
    WAITING = "waiting"
    READY = "ready"


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    kind: str
    version: str
    value: str
    value_digest: str
    owner_job_id: str


@dataclass(frozen=True, slots=True)
class CandidateEvidence:
    """A projection of one run-job link, never an ORM entity."""

    run_id: str
    run_started_at: datetime | str
    run_state: str
    run_policy_version: str
    run_snapshot_json: Any
    run_snapshot_hash: str
    link_id: str
    operation_id: str
    job_id: str
    disposition: str
    operation_run_id: str | None
    operation_source_id: str | None
    operation_result_state: str | None
    operation_finished_at: datetime | str | None
    operation_created_count: int = 0
    operation_observed_count: int = 0
    run_created_count: int = 0
    run_observed_count: int = 0
    source_snapshot_json: Any = None
    accepted_observation_at: datetime | str | None = None
    provider_recency_at: datetime | str | None = None
    recency_semantic: str | None = None
    freshness_policy_version: str | None = None
    identity_policy_version: str | None = None
    provenance_hash: str | None = None
    title: str | None = None
    company: str | None = None
    location: str | None = None
    description: str | None = None
    application_url: str | None = None
    identity_keys: tuple[IdentityEvidence, ...] = ()
    source_type: str | None = None
    source_key: str | None = None
    ignored_link_ids: tuple[str, ...] = ()
    job_exists: bool = True


@dataclass(frozen=True, slots=True)
class BoundaryResolution:
    run_id: str
    started_at_utc: str
    run_state: str
    inclusive: bool = True


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    boundary: BoundaryResolution
    fingerprint: str
    deployment: Mapping[str, str]
    runs: tuple[Mapping[str, Any], ...]
    operations: tuple[Mapping[str, Any], ...]
    links: tuple[Mapping[str, Any], ...]
    jobs: tuple[Mapping[str, Any], ...]
    identities: tuple[Mapping[str, Any], ...]
    profile: Mapping[str, Any]
    alembic_version: str
    candidates: tuple[CandidateEvidence, ...] = ()
    # v2 is additive so the historical v1 SnapshotStore contract remains
    # constructible by old callers and fixtures.
    upper_boundary: BoundaryResolution | None = None
    bounded_fingerprint_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class SelectionResult:
    status: CohortStatus
    eligible_count: int
    selected_count: int
    rejection_counts: Mapping[str, int]
    candidates: tuple[CandidateEvidence, ...]
    selected: tuple[CandidateEvidence, ...]
    candidate_cohort_sha256: str
    selection_sha256: str | None
    item_semantic_sha256: tuple[str, ...] = ()
    ignored_link_counts: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PreviewResult:
    payload: Mapping[str, Any]
    preview_sha256: str | None
    selection: SelectionResult
    snapshot: RepositorySnapshot


@dataclass(frozen=True, slots=True)
class DeploymentIdentity:
    code_commit: str = "unknown"
    clean: bool = True
    alembic_head: str = "f101b_continuous"


@dataclass(frozen=True, slots=True)
class FrozenBundle:
    dataset_id: str
    path: str
    internal_manifest: Mapping[str, Any]
    external_manifest: Mapping[str, Any]
    dataset_sha256: str
    provenance_sha256: str
    label_view_sha256: str


@dataclass(frozen=True, slots=True)
class ResolvedBoundaries:
    lower: BoundaryResolution
    upper: BoundaryResolution
    lower_key: tuple[str, str]
    upper_key: tuple[str, str]

    def __post_init__(self) -> None:
        if not self.lower.inclusive or not self.upper.inclusive:
            raise ValueError("boundaries_must_be_inclusive")
        if self.lower_key > self.upper_key:
            raise ValueError("boundaries_inverted")


@dataclass(frozen=True, slots=True)
class BoundedRepositorySnapshot(RepositorySnapshot):
    boundaries: ResolvedBoundaries | None = None


@dataclass(frozen=True, slots=True)
class CorpusItem:
    evidence: CandidateEvidence
    source_stratum: str
    strong_identity_digest: str
    item_semantic_sha256: str


@dataclass(frozen=True, slots=True)
class CorpusResult:
    status: str
    items: tuple[CorpusItem, ...]
    eligible_count: int
    rejection_counts: Mapping[str, int]
    ignored_link_counts: Mapping[str, int]
    corpus_sha256: str | None


@dataclass(frozen=True, slots=True)
class SourceQuota:
    source_stratum: str
    population: int
    minimum_applied: int
    ideal_numerator: int
    ideal_denominator: int
    floor: int
    remainder_numerator: int
    remainder_denominator: int
    tie_break_sha256: str
    quota: int


@dataclass(frozen=True, slots=True)
class PartitionResult:
    pilot: tuple[CorpusItem, ...]
    holdout: tuple[CorpusItem, ...]
    quotas: tuple[SourceQuota, ...]
    pilot_sha256: str
    holdout_sha256: str
    quota_sha256: str
    algorithm_version: str


@dataclass(frozen=True, slots=True)
class PreviewV2:
    payload: Mapping[str, Any]
    preview_sha256: str | None
    corpus: CorpusResult
    partition: PartitionResult | None
    snapshot: RepositorySnapshot


@dataclass(frozen=True, slots=True)
class FrozenBundleV2:
    dataset_id: str
    path: str
    internal_manifest: Mapping[str, Any]
    external_manifest: Mapping[str, Any]
    corpus_sha256: str
    pilot_sha256: str
    holdout_sha256: str


__all__ = [
    "BoundaryResolution",
    "BoundedRepositorySnapshot",
    "CandidateEvidence",
    "CohortStatus",
    "CorpusItem",
    "CorpusResult",
    "DeploymentIdentity",
    "FrozenBundle",
    "FrozenBundleV2",
    "IdentityEvidence",
    "PartitionResult",
    "PreviewResult",
    "PreviewV2",
    "RepositorySnapshot",
    "ResolvedBoundaries",
    "SelectionResult",
    "SourceQuota",
]
