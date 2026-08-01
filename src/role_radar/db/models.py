"""Modelos ORM de role-radar (solo mapeo, sin reglas de negocio).

Contratos Fase 1 (spec phase-01 §6). Enums importados de ``domain.enums``.
IDs UUID string (D5: ``str(uuid4())`` con guiones), timestamps UTC timezone-aware.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from role_radar.db.base import Base
from role_radar.domain.enums import (
    JobSearchRunStatus,
    JobStatus,
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

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[int] = mapped_column(default=1)
    profile_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


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
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    source_references: Mapped[list[JobSourceReference]] = relationship(
        back_populates="source"
    )


class Job(Base):
    """Oferta canónica deduplicada (un Job puede tener varias fuentes)."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255))
    company: Mapped[str] = mapped_column(String(255))
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    normalized_location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(nullable=True)
    application_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, native_enum=False, length=16, values_callable=_enum_values),
        default=JobStatus.NEW,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    source_references: Mapped[list[JobSourceReference]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )
    run_jobs: Mapped[list[RunJob]] = relationship(back_populates="job")


class JobSourceReference(Base):
    """Referencia de un Job a una Source concreta (collect)."""

    __tablename__ = "job_source_references"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    job: Mapped[Job] = relationship(back_populates="source_references")
    source: Mapped[Source] = relationship(back_populates="source_references")


class JobSearchRun(Base):
    """Ejecución del pipeline (D12: 10 estados exactos)."""

    __tablename__ = "job_search_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    reason: Mapped[str] = mapped_column(String(255))
    status: Mapped[JobSearchRunStatus] = mapped_column(
        Enum(
            JobSearchRunStatus,
            native_enum=False,
            length=24,
            values_callable=_enum_values,
        ),
        default=JobSearchRunStatus.PENDING,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(nullable=True)
    stats_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    run_jobs: Mapped[list[RunJob]] = relationship(back_populates="run")


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    run: Mapped[JobSearchRun] = relationship(back_populates="run_jobs")
    job: Mapped[Job] = relationship(back_populates="run_jobs")
