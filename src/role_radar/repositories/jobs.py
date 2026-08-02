"""Persistencia de ofertas (Job) y referencias a fuentes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, selectinload

from role_radar.db.models import Job, JobSourceReference
from role_radar.domain.enums import JobStatus

JobList = list[Job]


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
        description_hash: str | None = None,
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
            description_hash=description_hash,
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

    def list_with_description(self, *, limit: int = 50, offset: int = 0) -> JobList:
        """Lista ofertas que pueden entrar en extracción, sin reglas de estado."""
        stmt = (
            select(Job)
            .where(Job.description.is_not(None), Job.description != "")
            .order_by(Job.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._session.scalars(stmt))

    def update_last_seen(
        self, job_id: str, *, last_seen_at: datetime | None = None
    ) -> Job | None:
        job = self._session.get(Job, job_id)
        if job is None:
            return None
        job.last_seen_at = last_seen_at or datetime.now(UTC)
        self._session.flush()
        return job

    def find_by_source_external_id(self, source_id: str, external_id: str) -> Job | None:
        stmt = (
            select(Job)
            .join(JobSourceReference)
            .where(
                JobSourceReference.source_id == source_id,
                JobSourceReference.external_id == external_id,
            )
        )
        return self._session.scalars(stmt).first()

    def find_by_application_url(self, url: str | None) -> Job | None:
        if not url:
            return None
        return self._session.scalars(select(Job).where(Job.application_url == url)).first()

    def find_by_source_url(self, url: str | None) -> Job | None:
        if not url:
            return None
        stmt = select(Job).join(JobSourceReference).where(JobSourceReference.source_url == url)
        return self._session.scalars(stmt).first()

    def find_by_company_title_location(
        self, company: str, title: str, location: str | None
    ) -> Job | None:
        location_condition = (
            and_(Job.normalized_location.is_(None), Job.location.is_(None))
            if location is None
            else (
                func.lower(Job.normalized_location) == location.casefold()
            )
        )
        if location is not None:
            location_condition = (
                location_condition
                | and_(
                    Job.normalized_location.is_(None),
                    func.lower(Job.location) == location.casefold(),
                )
            )
        stmt = select(Job).where(
            and_(
                func.lower(Job.company) == company.casefold(),
                func.lower(Job.title) == title.casefold(),
                location_condition,
            )
        )
        return self._session.scalars(stmt).first()

    def find_by_description_hash(self, description_hash: str | None) -> Job | None:
        if not description_hash:
            return None
        return self._session.scalars(
            select(Job).where(Job.description_hash == description_hash)
        ).first()

    def find_source_reference(
        self, *, job_id: str, source_id: str, external_id: str | None
    ) -> JobSourceReference | None:
        external_condition = (
            JobSourceReference.external_id.is_(None)
            if external_id is None
            else JobSourceReference.external_id == external_id
        )
        stmt = select(JobSourceReference).where(
            JobSourceReference.job_id == job_id,
            JobSourceReference.source_id == source_id,
            external_condition,
        )
        return self._session.scalars(stmt).first()

    def touch_source_reference(
        self,
        ref_id: str,
        *,
        collected_at: datetime,
        raw_payload: dict[str, Any] | None,
        source_url: str | None,
    ) -> JobSourceReference:
        reference = self._session.get(JobSourceReference, ref_id)
        if reference is None:
            raise LookupError(f"source reference not found: {ref_id}")
        reference.collected_at = collected_at
        reference.raw_payload = raw_payload
        reference.source_url = source_url
        self._session.flush()
        return reference

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
