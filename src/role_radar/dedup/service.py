"""Reglas D6 de deduplicación, aisladas de HTTP y CLI."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from role_radar.db.models import Job
from role_radar.domain.dto import NormalizedJob
from role_radar.repositories.jobs import JobRepository


@dataclass(frozen=True)
class DedupResult:
    job: Job
    is_new: bool
    matched_by: str | None


class DedupService:
    def __init__(self, jobs: JobRepository) -> None:
        self._jobs = jobs

    def resolve(
        self,
        *,
        normalized: NormalizedJob,
        source_id: str,
        raw_payload: dict[str, Any] | None = None,
    ) -> DedupResult:
        job, matched_by = self._find_match(normalized, source_id)

        now = datetime.now(UTC)
        payload = raw_payload if raw_payload is not None else normalized.structured_data
        if job is not None:
            self._jobs.update_last_seen(job.id, last_seen_at=now)
            reference = self._jobs.find_source_reference(
                job_id=job.id, source_id=source_id, external_id=normalized.external_id
            )
            if reference is None:
                self._jobs.add_source_reference(
                    job_id=job.id,
                    source_id=source_id,
                    external_id=normalized.external_id,
                    source_url=normalized.source_url,
                    raw_payload=payload,
                )
            else:
                self._jobs.touch_source_reference(
                    reference.id,
                    collected_at=now,
                    raw_payload=payload,
                    source_url=normalized.source_url,
                )
            return DedupResult(job=job, is_new=False, matched_by=matched_by)

        job = self._jobs.create(
            title=normalized.title,
            company=normalized.company,
            location=normalized.location,
            normalized_location=normalized.normalized_location,
            description=normalized.description,
            description_hash=normalized.description_hash,
            application_url=normalized.application_url,
            first_seen_at=now,
            last_seen_at=now,
        )
        self._jobs.add_source_reference(
            job_id=job.id,
            source_id=source_id,
            external_id=normalized.external_id,
            source_url=normalized.source_url,
            raw_payload=payload,
        )
        return DedupResult(job=job, is_new=True, matched_by=None)

    def _find_match(
        self, normalized: NormalizedJob, source_id: str
    ) -> tuple[Job | None, str | None]:
        candidate = self._jobs.find_by_source_external_id(source_id, normalized.external_id)
        if candidate is not None:
            return candidate, "source_external_id"
        if normalized.application_url:
            candidate = self._jobs.find_by_application_url(normalized.application_url)
            if candidate is not None:
                return candidate, "application_url"
        if normalized.source_url:
            candidate = self._jobs.find_by_source_url(normalized.source_url)
            if candidate is not None:
                return candidate, "source_url"
        candidate = self._jobs.find_by_company_title_location(
            normalized.company, normalized.title, normalized.normalized_location
        )
        if candidate is not None:
            return candidate, "company_title_location"
        if normalized.description_hash:
            candidate = self._jobs.find_by_description_hash(normalized.description_hash)
            if candidate is not None:
                return candidate, "description_hash"
        return None, None
