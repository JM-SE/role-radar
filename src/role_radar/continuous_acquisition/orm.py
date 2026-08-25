"""SQLAlchemy mappings for the continuous acquisition journal.

The mappings are intentionally flat.  State transitions and fencing decisions
belong to repositories, not ORM event hooks or a service aggregate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from role_radar.db.base import Base


def _uuid() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class SourceDiscoveryRun(Base):
    __tablename__ = "source_discovery_runs"
    __table_args__ = (
        UniqueConstraint("slot_key", name="uq_source_discovery_runs_slot_key"),
        CheckConstraint(
            "state IN ('planned','running','completed','partial','failed','indeterminate')",
            name="ck_source_discovery_runs_state",
        ),
        CheckConstraint(
            "candidate_count >= 0 AND reserved_count >= 0 AND verified_count >= 0 AND registered_count >= 0",
            name="ck_source_discovery_runs_counts",
        ),
        Index("ix_source_discovery_runs_state", "state"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slot_key: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="planned")
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    config_version: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    fencing_generation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    candidate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reserved_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verified_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    registered_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    truncated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    terminal_code: Mapped[str | None] = mapped_column(String(64), nullable=True)


class SourceDiscoveryOperation(Base):
    __tablename__ = "source_discovery_operations"
    __table_args__ = (
        UniqueConstraint("run_id", "operation_key", name="uq_source_discovery_operations_key"),
        CheckConstraint(
            "intent_state IN ('intent','succeeded','failed','indeterminate')",
            name="ck_source_discovery_operations_intent",
        ),
        CheckConstraint(
            "result_state IS NULL OR result_state IN ('succeeded','empty','failed','indeterminate')",
            name="ck_source_discovery_operations_result",
        ),
        CheckConstraint(
            "reserved_capacity >= 0 AND attempts >= 0 AND candidate_count >= 0 AND verified_count >= 0",
            name="ck_source_discovery_operations_counts",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("source_discovery_runs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    operation_key: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    operation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    intent_state: Mapped[str] = mapped_column(String(20), nullable=False, default="intent")
    result_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reserved_capacity: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    candidate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verified_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SourceDiscoveryRegistration(Base):
    __tablename__ = "source_discovery_registrations"
    __table_args__ = (
        UniqueConstraint("run_id", "source_key", name="uq_source_discovery_registrations_source"),
        CheckConstraint(
            "disposition IN ('created','existing_enabled','existing_disabled','existing_archived','conflict')",
            name="ck_source_discovery_registrations_disposition",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("source_discovery_runs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    operation_id: Mapped[str] = mapped_column(
        ForeignKey("source_discovery_operations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[str | None] = mapped_column(
        ForeignKey("sources.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    source_key: Mapped[str] = mapped_column(String(255), nullable=False)
    disposition: Mapped[str] = mapped_column(String(24), nullable=False)
    previous_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    management_origin: Mapped[str] = mapped_column(String(16), nullable=False, default="discovery")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ContinuousAcquisitionRun(Base):
    __tablename__ = "continuous_acquisition_runs"
    __table_args__ = (
        UniqueConstraint("slot_key", name="uq_continuous_acquisition_runs_slot_key"),
        CheckConstraint(
            "state IN ('completed','completed_empty','completed_partial','failed','indeterminate','planned','running')",
            name="ck_continuous_acquisition_runs_state",
        ),
        CheckConstraint(
            "observed_count >= 0 AND created_count >= 0 AND duplicate_count >= 0 AND stale_count >= 0 AND invalid_count >= 0 AND conflict_count >= 0",
            name="ck_continuous_acquisition_runs_counts",
        ),
        Index("ix_continuous_acquisition_runs_state", "state"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    slot_key: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="planned")
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    snapshot_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    fencing_generation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reserved_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attempted_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completed_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    truncated_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    observed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stale_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    invalid_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    conflict_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    terminal_code: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ContinuousAcquisitionSourceOperation(Base):
    __tablename__ = "continuous_acquisition_source_operations"
    __table_args__ = (
        UniqueConstraint("run_id", "source_id", name="uq_continuous_acquisition_source_operation"),
        CheckConstraint(
            "intent_state IN ('intent','succeeded','empty','failed','truncated','indeterminate')",
            name="ck_continuous_acquisition_source_operations_intent",
        ),
        CheckConstraint(
            "result_state IS NULL OR result_state IN ('succeeded','empty','failed','truncated','indeterminate')",
            name="ck_continuous_acquisition_source_operations_result",
        ),
        CheckConstraint(
            "observed_count >= 0 AND created_count >= 0 AND duplicate_count >= 0 AND stale_count >= 0 AND invalid_count >= 0 AND conflict_count >= 0",
            name="ck_continuous_acquisition_source_operations_counts",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("continuous_acquisition_runs.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    source_id: Mapped[str] = mapped_column(
        ForeignKey("sources.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    source_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    intent_state: Mapped[str] = mapped_column(String(20), nullable=False, default="intent")
    result_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    page_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    observed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    stale_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    invalid_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    conflict_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    truncated: Mapped[bool] = mapped_column(default=False, nullable=False)
    continuation_evidence: Mapped[str | None] = mapped_column(String(255), nullable=True)
    result_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ContinuousAcquisitionRunJob(Base):
    __tablename__ = "continuous_acquisition_run_jobs"
    __table_args__ = (
        UniqueConstraint("run_id", "job_id", name="uq_continuous_acquisition_run_job"),
        CheckConstraint(
            "disposition IN ('created','duplicate')",
            name="ck_continuous_acquisition_run_jobs_disposition",
        ),
        Index("ix_continuous_acquisition_run_jobs_operation", "operation_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("continuous_acquisition_runs.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    operation_id: Mapped[str] = mapped_column(
        ForeignKey("continuous_acquisition_source_operations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    job_id: Mapped[str] = mapped_column(
        ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    disposition: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_recency_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recency_semantic: Mapped[str] = mapped_column(String(64), nullable=False)
    freshness_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class JobIdentityKey(Base):
    __tablename__ = "job_identity_keys"
    __table_args__ = (
        UniqueConstraint(
            "identity_version",
            "identity_kind",
            "identity_value",
            name="uq_job_identity_keys_strong",
        ),
        Index("ix_job_identity_keys_job", "job_id"),
        Index("ix_job_identity_keys_digest", "value_digest"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), nullable=False)
    identity_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    identity_version: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    value_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
