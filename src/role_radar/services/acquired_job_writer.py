"""Shared synchronous RawJob writer used by ATS collection and discovery."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from role_radar.dedup.service import DedupService
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import RunJobStage, RunJobStatus
from role_radar.normalization.jobs import normalize_raw_job
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository


@dataclass(frozen=True, slots=True)
class AcquiredWriteResult:
    accepted: int
    new_jobs: int
    duplicates: int
    prefiltered: int
    job_ids: tuple[str, ...]


class AcquiredJobWriter:
    """All ORM access is synchronous and the caller owns the transaction."""

    def __init__(self, session: Session) -> None:
        self._jobs = JobRepository(session)
        self._runs = RunRepository(session)
        self._dedup = DedupService(self._jobs)

    def write(
        self,
        *,
        run_id: str,
        source_id: str,
        raw_jobs: tuple[RawJob, ...],
        acquisition: str = "ats",
        cycle_id: str | None = None,
    ) -> AcquiredWriteResult:
        new_jobs = duplicates = prefiltered = 0
        ids: list[str] = []
        for raw_job in raw_jobs:
            normalized = normalize_raw_job(raw_job)
            if not normalized.title or not normalized.description or not (
                normalized.application_url or normalized.source_url
            ):
                prefiltered += 1
                continue
            resolved = self._dedup.resolve(
                normalized=normalized,
                source_id=source_id,
                raw_payload=raw_job.structured_data,
            )
            ids.append(resolved.job.id)
            if resolved.is_new:
                new_jobs += 1
            else:
                duplicates += 1
            outcome: dict[str, Any] | None = None
            if acquisition == "discovery" and cycle_id is not None:
                outcome = {"acquisition": "discovery", "cycle_id": cycle_id, "source_id": source_id}
            for stage in (RunJobStage.COLLECTED, RunJobStage.NORMALIZED, RunJobStage.DEDUPLICATED):
                self._runs.update_run_job(
                    run_id=run_id,
                    job_id=resolved.job.id,
                    stage=stage,
                    status=RunJobStatus.SUCCEEDED,
                    outcome_json=outcome if stage is RunJobStage.DEDUPLICATED else None,
                )
        return AcquiredWriteResult(
            accepted=len(ids),
            new_jobs=new_jobs,
            duplicates=duplicates,
            prefiltered=prefiltered,
            job_ids=tuple(ids),
        )
