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


__all__ = [
    "BoundaryResolution",
    "CandidateEvidence",
    "CohortStatus",
    "DeploymentIdentity",
    "FrozenBundle",
    "IdentityEvidence",
    "PreviewResult",
    "RepositorySnapshot",
    "SelectionResult",
]
