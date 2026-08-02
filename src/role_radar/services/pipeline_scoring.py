"""Etapa sync de scoring con perfil fijado en el run."""

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import JobScore, JobSearchRun, RunJob
from role_radar.domain.enums import RunJobStage, RunJobStatus
from role_radar.repositories.runs import RunRepository
from role_radar.services.matching_service import MatchingService


class PipelineScoringService:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def score(self, run_id: str, job_ids: list[str]) -> None:
        for job_id in job_ids:
            with self._session_factory() as session:
                run = session.get(JobSearchRun, run_id)
                if run is None:
                    raise LookupError("run not found")
                if run.profile_id is None:
                    RunRepository(session).update_run_job(
                        run_id=run_id,
                        job_id=job_id,
                        stage=RunJobStage.SCORED,
                        status=RunJobStatus.FAILED,
                        error_code="profile_missing",
                    )
                    session.commit()
                    continue
                existing = session.scalar(
                    select(RunJob).where(
                        RunJob.run_id == run_id,
                        RunJob.job_id == job_id,
                        RunJob.stage == RunJobStage.SCORED,
                    )
                )
                if existing is not None and existing.status is RunJobStatus.SUCCEEDED:
                    if not (existing.outcome_json or {}).get("job_score_id"):
                        persisted = session.scalar(
                            select(JobScore)
                            .where(JobScore.job_id == job_id, JobScore.profile_id == run.profile_id)
                            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
                        )
                        if persisted is not None:
                            existing.outcome_json = {
                                **(existing.outcome_json or {}),
                                "job_score_id": persisted.id,
                                "eligible": persisted.eligible,
                                "score": persisted.preliminary_score,
                            }
                            session.commit()
                    continue
                try:
                    score = MatchingService(session).score_job(
                        job_id=job_id, profile_id=run.profile_id
                    )
                    RunRepository(session).update_run_job(
                        run_id=run_id,
                        job_id=job_id,
                        stage=RunJobStage.SCORED,
                        status=RunJobStatus.SUCCEEDED,
                        outcome_json={
                            "job_score_id": score.id,
                            "eligible": score.eligible,
                            "score": score.preliminary_score,
                        },
                    )
                except Exception:
                    RunRepository(session).update_run_job(
                        run_id=run_id,
                        job_id=job_id,
                        stage=RunJobStage.SCORED,
                        status=RunJobStatus.FAILED,
                        error_code="score_failed",
                    )
                session.commit()
