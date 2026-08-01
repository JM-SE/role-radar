"""Persistencia de ofertas (Job) y referencias a fuentes."""

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from role_radar.db.models import Job, JobSourceReference
from role_radar.domain.enums import JobStatus


class JobRepository:
    """I/O de Job y JobSourceReference. Sin reglas de negocio ni commit propio."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        title: str,
        company: str,
        status: JobStatus = JobStatus.NEW,
        location: str | None = None,
        normalized_location: str | None = None,
        description: str | None = None,
        application_url: str | None = None,
        first_seen_at: datetime | None = None,
        last_seen_at: datetime | None = None,
        published_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> Job:
        job = Job(
            title=title,
            company=company,
            status=status,
            location=location,
            normalized_location=normalized_location,
            description=description,
            application_url=application_url,
            first_seen_at=first_seen_at,
            last_seen_at=last_seen_at,
            published_at=published_at,
            expires_at=expires_at,
        )
        self._session.add(job)
        self._session.flush()
        return job

    def get(self, job_id: str) -> Job | None:
        stmt = (
            select(Job)
            .where(Job.id == job_id)
            .options(selectinload(Job.source_references))
        )
        return self._session.scalars(stmt).first()

    def list(
        self,
        *,
        status: JobStatus | None = None,
        company: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Job]:
        stmt = select(Job).order_by(Job.last_seen_at.desc()).limit(limit).offset(offset)
        if status is not None:
            stmt = stmt.where(Job.status == status)
        if company is not None:
            stmt = stmt.where(Job.company == company)
        return list(self._session.scalars(stmt))

    def add_source_reference(
        self,
        *,
        job_id: str,
        source_id: str,
        external_id: str | None = None,
        source_url: str | None = None,
        raw_payload: dict[str, Any] | None = None,
    ) -> JobSourceReference:
        reference = JobSourceReference(
            job_id=job_id,
            source_id=source_id,
            external_id=external_id,
            source_url=source_url,
            raw_payload=raw_payload,
        )
        self._session.add(reference)
        self._session.flush()
        return reference
