"""Modelos ORM de role-radar (solo mapeo, sin reglas de negocio).

Contratos Fase 1 (spec phase-01 §6). Enums importados de ``domain.enums``.
IDs UUID string (D5: ``str(uuid4())`` con guiones), timestamps UTC timezone-aware.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from role_radar.db.base import Base
from role_radar.domain.enums import (
    DeepEvaluationStatus,
    ExtractionStatus,
    JobSearchRunStatus,
    JobStatus,
    NotificationBatchStatus,
    NotificationItemStatus,
    NotificationMode,
    RunJobStage,
    RunJobStatus,
    SourceType,
)


def _uuid() -> str:
    return str(uuid4())


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _enum_values(enum_cls: type[StrEnum]) -> list[str]:
    """Valores de StrEnum como lista (para almacenar el valor, no el nombre)."""
    return [member.value for member in enum_cls.__members__.values()]


class CandidateProfile(Base):
    """Perfil profesional del candidato (D3: semilla manual JSON reducido)."""

    __tablename__ = "candidate_profiles"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_candidate_profiles_name_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[int] = mapped_column(default=1)
    schema_version: Mapped[int] = mapped_column(default=0)
    profile_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scores: Mapped[list[JobScore]] = relationship(back_populates="profile")
    deep_evaluations: Mapped[list[JobDeepEvaluation]] = relationship(back_populates="profile")


class Source(Base):
    """Fuente de ofertas (board ATS, web, email, manual...)."""

    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    type: Mapped[SourceType] = mapped_column(
        Enum(SourceType, native_enum=False, length=24, values_callable=_enum_values)
    )
    name: Mapped[str] = mapped_column(String(255), unique=True)
    configuration: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    source_references: Mapped[list[JobSourceReference]] = relationship(back_populates="source")


class Job(Base):
    """Oferta canónica deduplicada (un Job puede tener varias fuentes)."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255))
    company: Mapped[str] = mapped_column(String(255))
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    normalized_location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(nullable=True)
    description_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    application_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=JobStatus.NEW,
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    source_references: Mapped[list[JobSourceReference]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    run_jobs: Mapped[list[RunJob]] = relationship(back_populates="job")
    extractions: Mapped[list[JobExtraction]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    scores: Mapped[list[JobScore]] = relationship(back_populates="job")
    deep_evaluations: Mapped[list[JobDeepEvaluation]] = relationship(back_populates="job")
    deep_queue_items: Mapped[list[DeepEvaluationQueueItem]] = relationship(back_populates="job")


class JobExtraction(Base):
    """Resultado durable de una extracción, sin prompts ni output inválido."""

    __tablename__ = "job_extractions"
    __table_args__ = (
        UniqueConstraint(
            "job_id",
            "input_hash",
            "schema_version",
            "prompt_version",
            name="uq_job_extractions_operation",
        ),
        CheckConstraint(
            "active_corrective_attempt IN (0, 1)",
            name="ck_job_extractions_active_corrective_attempt",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"), index=True)
    schema_version: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(64))
    model_capability: Mapped[str] = mapped_column(String(64))
    model_identifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    broker_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    input_hash: Mapped[str] = mapped_column(String(64))
    extraction_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    validation_status: Mapped[ExtractionStatus] = mapped_column(
        Enum(ExtractionStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=ExtractionStatus.PENDING,
    )
    attempt_count: Mapped[int] = mapped_column(default=0)
    active_corrective_attempt: Mapped[int] = mapped_column(default=0)
    request_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    processing_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    finish_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    usage_json: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    job: Mapped[Job] = relationship(back_populates="extractions")
    scores: Mapped[list[JobScore]] = relationship(back_populates="extraction")


class JobScore(Base):
    """Immutable result of one deterministic matching operation."""

    __tablename__ = "job_scores"
    __table_args__ = (
        UniqueConstraint("operation_key", name="uq_job_scores_operation_key"),
        CheckConstraint(
            "preliminary_score >= 0 AND preliminary_score <= 100", name="ck_job_scores_score_range"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), index=True)
    profile_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_profiles.id", ondelete="RESTRICT"), index=True
    )
    extraction_id: Mapped[str | None] = mapped_column(
        ForeignKey("job_extractions.id", ondelete="RESTRICT"), index=True, nullable=True
    )
    operation_key: Mapped[str] = mapped_column(String(512), unique=True)
    scoring_version: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(64))
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    preliminary_score: Mapped[int] = mapped_column()
    eligible: Mapped[bool] = mapped_column()
    signal_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    hard_blocker_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    ambiguity_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    job: Mapped[Job] = relationship(back_populates="scores")
    profile: Mapped[CandidateProfile] = relationship(back_populates="scores")
    extraction: Mapped[JobExtraction | None] = relationship(back_populates="scores")
    deep_evaluations: Mapped[list[JobDeepEvaluation]] = relationship(back_populates="job_score")


class DeepEvaluationQueueItem(Base):
    """Immutable, durable selection made for one run."""

    __tablename__ = "deep_evaluation_queue"
    __table_args__ = (
        UniqueConstraint("run_id", "job_id", name="uq_deep_queue_run_job"),
        UniqueConstraint("run_id", "rank", name="uq_deep_queue_run_rank"),
        UniqueConstraint("run_id", "job_score_id", name="uq_deep_queue_run_score"),
        CheckConstraint("rank >= 1 AND rank <= 10", name="ck_deep_queue_rank"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("job_search_runs.id", ondelete="RESTRICT"), index=True
    )
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), index=True)
    job_score_id: Mapped[str] = mapped_column(
        ForeignKey("job_scores.id", ondelete="RESTRICT"), index=True
    )
    rank: Mapped[int] = mapped_column()
    selection_reason: Mapped[str] = mapped_column(String(32))
    selector_policy_version: Mapped[str] = mapped_column(String(64))
    selector_policy_hash: Mapped[str] = mapped_column(String(64))
    ambiguity_resolution_version: Mapped[str] = mapped_column(String(64))
    selection_input_hash: Mapped[str] = mapped_column(String(64), index=True)
    resolvable_ambiguity_codes_json: Mapped[list[str]] = mapped_column(JSON)
    evaluation_id: Mapped[str | None] = mapped_column(
        ForeignKey("job_deep_evaluations.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run: Mapped[JobSearchRun] = relationship(back_populates="deep_queue_items")
    job: Mapped[Job] = relationship(back_populates="deep_queue_items")
    score: Mapped[JobScore] = relationship()
    evaluation: Mapped[JobDeepEvaluation | None] = relationship(foreign_keys=[evaluation_id])


class JobDeepEvaluation(Base):
    """Historical operation whose terminal result is never overwritten."""

    __tablename__ = "job_deep_evaluations"
    __table_args__ = (
        UniqueConstraint("operation_key", name="uq_job_deep_evaluations_operation_key"),
        CheckConstraint("attempt_count >= 0 AND attempt_count <= 2", name="ck_deep_attempt_count"),
        CheckConstraint("active_corrective_attempt IN (0, 1)", name="ck_deep_corrective_attempt"),
        CheckConstraint(
            "fit_score IS NULL OR (fit_score >= 0 AND fit_score <= 100)", name="ck_deep_fit_score"
        ),
        CheckConstraint(
            "final_score IS NULL OR (final_score >= 0 AND final_score <= 100)",
            name="ck_deep_final_score",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), index=True)
    profile_id: Mapped[str] = mapped_column(
        ForeignKey("candidate_profiles.id", ondelete="RESTRICT"), index=True
    )
    extraction_id: Mapped[str] = mapped_column(
        ForeignKey("job_extractions.id", ondelete="RESTRICT"), index=True
    )
    job_score_id: Mapped[str] = mapped_column(
        ForeignKey("job_scores.id", ondelete="RESTRICT"), index=True
    )
    operation_key: Mapped[str] = mapped_column(String(512), unique=True)
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    prompt_version: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(64))
    selector_policy_version: Mapped[str] = mapped_column(String(64))
    selector_policy_hash: Mapped[str] = mapped_column(String(64))
    model_capability: Mapped[str] = mapped_column(String(64))
    model_identifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    broker_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    status: Mapped[DeepEvaluationStatus] = mapped_column(
        Enum(DeepEvaluationStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=DeepEvaluationStatus.PENDING,
    )
    attempt_count: Mapped[int] = mapped_column(default=0)
    active_corrective_attempt: Mapped[int] = mapped_column(default=0)
    request_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    processing_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fit_score: Mapped[int | None] = mapped_column(nullable=True)
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    strengths_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    gaps_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    model_concerns_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    uncertainties_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(nullable=True)
    adjustment: Mapped[int | None] = mapped_column(nullable=True)
    final_score: Mapped[int | None] = mapped_column(nullable=True)
    finish_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    usage_json: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)
    error_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    job: Mapped[Job] = relationship(back_populates="deep_evaluations")
    profile: Mapped[CandidateProfile] = relationship(back_populates="deep_evaluations")
    extraction: Mapped[JobExtraction] = relationship()
    job_score: Mapped[JobScore] = relationship(back_populates="deep_evaluations")


class JobSourceReference(Base):
    """Referencia de un Job a una Source concreta (collect)."""

    __tablename__ = "job_source_references"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    job: Mapped[Job] = relationship(back_populates="source_references")
    source: Mapped[Source] = relationship(back_populates="source_references")


class JobSearchRun(Base):
    """Ejecución del pipeline (D12: 10 estados exactos)."""

    __tablename__ = "job_search_runs"
    __table_args__ = (
        Index("ix_job_search_runs_pending_created", "status", "created_at"),
        Index(
            "ix_job_search_runs_recovery",
            "status",
            "lease_expires_at",
            "created_at",
        ),
        Index("ix_job_search_runs_profile", "profile_id"),
        Index("ix_job_search_runs_retry_parent", "retry_of_run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    reason: Mapped[str] = mapped_column(String(255))
    notification_mode: Mapped[NotificationMode] = mapped_column(
        Enum(NotificationMode, native_enum=False, length=16, values_callable=_enum_values),
        default=NotificationMode.NONE,
        nullable=False,
    )
    schedule_slot: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("candidate_profiles.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    retry_of_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("job_search_runs.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    trigger_key_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
    request_hash: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    status: Mapped[JobSearchRunStatus] = mapped_column(
        Enum(
            JobSearchRunStatus,
            native_enum=False,
            length=24,
            values_callable=_enum_values,
        ),
        default=JobSearchRunStatus.PENDING,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stats_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    source_snapshot_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    source_results_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_count: Mapped[int] = mapped_column(default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    run_jobs: Mapped[list[RunJob]] = relationship(back_populates="run")
    deep_queue_items: Mapped[list[DeepEvaluationQueueItem]] = relationship(back_populates="run")
    profile: Mapped[CandidateProfile | None] = relationship(foreign_keys=[profile_id])
    retry_of: Mapped[JobSearchRun | None] = relationship(
        remote_side=[id], foreign_keys=[retry_of_run_id], uselist=False
    )


class RunJob(Base):
    """Journal por etapa de cada oferta dentro de una ejecución (D14)."""

    __tablename__ = "run_jobs"
    __table_args__ = (UniqueConstraint("run_id", "job_id", "stage"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("job_search_runs.id"))
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    stage: Mapped[RunJobStage] = mapped_column(
        Enum(RunJobStage, native_enum=False, length=24, values_callable=_enum_values)
    )
    status: Mapped[RunJobStatus] = mapped_column(
        Enum(RunJobStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=RunJobStatus.PENDING,
    )
    error_message: Mapped[str | None] = mapped_column(nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempt_count: Mapped[int] = mapped_column(default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    run: Mapped[JobSearchRun] = relationship(back_populates="run_jobs")
    job: Mapped[Job] = relationship(back_populates="run_jobs")


class NotificationBatch(Base):
    """Durable single-message Telegram outbox record."""

    __tablename__ = "notification_batches"
    __table_args__ = (
        UniqueConstraint("operation_key", name="uq_notification_batches_operation_key"),
        CheckConstraint(
            "item_count >= 1 AND item_count <= 5", name="ck_notification_batch_item_count"
        ),
        Index("ix_notification_batches_due", "status", "next_attempt_at"),
        Index("ix_notification_batches_run", "run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("job_search_runs.id", ondelete="RESTRICT"), index=True
    )
    schedule_slot: Mapped[str] = mapped_column(String(64))
    channel: Mapped[str] = mapped_column(String(24), default="telegram")
    recipient_key_hash: Mapped[str] = mapped_column(String(64))
    operation_key: Mapped[str] = mapped_column(String(512), unique=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    formatter_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[NotificationBatchStatus] = mapped_column(
        Enum(NotificationBatchStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=NotificationBatchStatus.PENDING,
    )
    body: Mapped[str | None] = mapped_column(nullable=True)
    body_hash: Mapped[str] = mapped_column(String(64), default="")
    body_length: Mapped[int] = mapped_column(default=0)
    item_count: Mapped[int] = mapped_column(default=1)
    attempt_count: Mapped[int] = mapped_column(default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sending_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    telegram_message_id: Mapped[int | None] = mapped_column(nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_status: Mapped[int | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    run: Mapped[JobSearchRun] = relationship()
    items: Mapped[list[NotificationItem]] = relationship(
        back_populates="batch", cascade="all, delete-orphan"
    )


class NotificationItem(Base):
    """Global per-recipient/job reservation and terminal outcome."""

    __tablename__ = "notification_items"
    __table_args__ = (
        UniqueConstraint("batch_id", "rank", name="uq_notification_items_batch_rank"),
        UniqueConstraint("batch_id", "job_id", name="uq_notification_items_batch_job"),
        UniqueConstraint(
            "channel", "recipient_key_hash", "job_id", name="uq_notification_items_global_job"
        ),
        CheckConstraint("rank >= 1 AND rank <= 5", name="ck_notification_item_rank"),
        Index("ix_notification_items_run", "run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    batch_id: Mapped[str] = mapped_column(
        ForeignKey("notification_batches.id", ondelete="RESTRICT"), index=True
    )
    run_id: Mapped[str] = mapped_column(
        ForeignKey("job_search_runs.id", ondelete="RESTRICT"), index=True
    )
    channel: Mapped[str] = mapped_column(String(24), default="telegram")
    recipient_key_hash: Mapped[str] = mapped_column(String(64))
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id", ondelete="RESTRICT"), index=True)
    job_score_id: Mapped[str] = mapped_column(ForeignKey("job_scores.id", ondelete="RESTRICT"))
    deep_evaluation_id: Mapped[str] = mapped_column(
        ForeignKey("job_deep_evaluations.id", ondelete="RESTRICT")
    )
    rank: Mapped[int] = mapped_column()
    status: Mapped[NotificationItemStatus] = mapped_column(
        Enum(NotificationItemStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=NotificationItemStatus.RESERVED,
    )
    outcome_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    batch: Mapped[NotificationBatch] = relationship(back_populates="items")
