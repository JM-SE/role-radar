"""Persistencia de ofertas (Job) y referencias a fuentes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, case, func, select
from sqlalchemy.orm import Session, selectinload

from role_radar.db.models import Job, JobDeepEvaluation, JobScore, JobSourceReference
from role_radar.domain.enums import JobStatus

JobList = list[Job]
JobScoreList = list[tuple[Job, JobScore]]
OptionalJobScoreList = list[tuple[Job, JobScore | None]]
DeepJobScoreList = list[tuple[Job, JobScore, JobDeepEvaluation | None]]


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
        stmt = select(Job).where(Job.id == job_id).options(selectinload(Job.source_references))
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

    def list_with_latest_scores(
        self,
        *,
        profile_id: str,
        status: JobStatus | None = None,
        company: str | None = None,
        minimum_score: int | None = None,
        eligible: bool | None = True,
        requires_review: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> JobScoreList:
        """One SQL query for rankable jobs and their latest score."""
        latest_id = (
            select(JobScore.id)
            .where(JobScore.job_id == Job.id, JobScore.profile_id == profile_id)
            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
            .limit(1)
            .correlate(Job)
            .scalar_subquery()
        )
        stmt = (
            select(Job, JobScore)
            .join(JobScore, JobScore.id == latest_id)
            .options(selectinload(Job.source_references))
            .order_by(JobScore.preliminary_score.desc(), Job.first_seen_at.desc(), Job.id.asc())
            .limit(limit)
            .offset(offset)
        )
        if status is not None:
            stmt = stmt.where(Job.status == status)
        if company is not None:
            stmt = stmt.where(Job.company == company)
        if minimum_score is not None:
            stmt = stmt.where(JobScore.preliminary_score >= minimum_score)
        if eligible is not None:
            stmt = stmt.where(JobScore.eligible.is_(eligible))
        if requires_review:
            stmt = stmt.where(func.json_array_length(JobScore.ambiguity_json) > 0)
        return list(self._session.execute(stmt).tuples().all())

    def list_with_optional_scores(
        self,
        *,
        profile_id: str,
        status: JobStatus | None = None,
        company: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> OptionalJobScoreList:
        latest_id = (
            select(JobScore.id)
            .where(JobScore.job_id == Job.id, JobScore.profile_id == profile_id)
            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
            .limit(1)
            .correlate(Job)
            .scalar_subquery()
        )
        stmt = (
            select(Job, JobScore)
            .outerjoin(JobScore, JobScore.id == latest_id)
            .options(selectinload(Job.source_references))
            .order_by(Job.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if status is not None:
            stmt = stmt.where(Job.status == status)
        if company is not None:
            stmt = stmt.where(Job.company == company)
        return list(self._session.execute(stmt).tuples().all())

    def latest_score(self, *, job_id: str, profile_id: str) -> JobScore | None:
        stmt = (
            select(JobScore)
            .where(JobScore.job_id == job_id, JobScore.profile_id == profile_id)
            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
            .limit(1)
        )
        return self._session.scalar(stmt)

    def latest_score_with_deep(
        self, *, job_id: str, profile_id: str
    ) -> tuple[JobScore | None, JobDeepEvaluation | None]:
        score = self.latest_score(job_id=job_id, profile_id=profile_id)
        if score is None:
            return None, None
        deep = self._session.scalar(
            select(JobDeepEvaluation)
            .where(JobDeepEvaluation.job_score_id == score.id)
            .order_by(JobDeepEvaluation.created_at.desc(), JobDeepEvaluation.id.asc())
            .limit(1)
        )
        return score, deep

    def list_with_effective_scores(
        self,
        *,
        profile_id: str,
        status: JobStatus | None = None,
        company: str | None = None,
        minimum_score: int | None = None,
        eligible: bool | None = True,
        requires_review: bool = False,
        decision: str | None = None,
        minimum_effective_score: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> DeepJobScoreList:
        latest_id = (
            select(JobScore.id)
            .where(JobScore.job_id == Job.id, JobScore.profile_id == profile_id)
            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
            .limit(1)
            .correlate(Job)
            .scalar_subquery()
        )
        deep_id = (
            select(JobDeepEvaluation.id)
            .where(
                JobDeepEvaluation.job_score_id == JobScore.id, JobDeepEvaluation.status == "valid"
            )
            .order_by(JobDeepEvaluation.created_at.desc(), JobDeepEvaluation.id.asc())
            .limit(1)
            .correlate(JobScore)
            .scalar_subquery()
        )
        effective = case(
            (JobDeepEvaluation.final_score.is_not(None), JobDeepEvaluation.final_score),
            else_=JobScore.preliminary_score,
        )
        stmt = (
            select(Job, JobScore, JobDeepEvaluation)
            .join(JobScore, JobScore.id == latest_id)
            .outerjoin(JobDeepEvaluation, JobDeepEvaluation.id == deep_id)
            .options(selectinload(Job.source_references))
        )
        if status is not None:
            stmt = stmt.where(Job.status == status)
        if company is not None:
            stmt = stmt.where(Job.company == company)
        if minimum_score is not None:
            stmt = stmt.where(JobScore.preliminary_score >= minimum_score)
        if eligible is not None:
            stmt = stmt.where(JobScore.eligible.is_(eligible))
        if requires_review:
            stmt = stmt.where(func.json_array_length(JobScore.ambiguity_json) > 0)
        if decision is not None:
            stmt = stmt.where(
                JobDeepEvaluation.decision == decision, JobDeepEvaluation.status == "valid"
            )
        if minimum_effective_score is not None:
            stmt = stmt.where(effective >= minimum_effective_score)
        if decision is not None or minimum_effective_score is not None:
            stmt = stmt.order_by(
                effective.desc(),
                JobScore.preliminary_score.desc(),
                Job.first_seen_at.desc(),
                Job.id.asc(),
            )
        else:
            stmt = stmt.order_by(
                JobScore.preliminary_score.desc(), Job.first_seen_at.desc(), Job.id.asc()
            )
        return list(self._session.execute(stmt.limit(limit).offset(offset)).tuples().all())

    def update_last_seen(self, job_id: str, *, last_seen_at: datetime | None = None) -> Job | None:
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
            else (func.lower(Job.normalized_location) == location.casefold())
        )
        if location is not None:
            location_condition = location_condition | and_(
                Job.normalized_location.is_(None),
                func.lower(Job.location) == location.casefold(),
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
