"""Secuenciador del pipeline; las reglas de cada etapa viven en services."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.broker.protocols import LLMProvider
from role_radar.config import Settings
from role_radar.db.models import JobExtraction, JobSearchRun, RunJob
from role_radar.domain.enums import (
    ExtractionStatus,
    JobSearchRunStatus,
    RunJobStage,
    RunJobStatus,
)
from role_radar.repositories.runs import RunRepository
from role_radar.services.pipeline_collection import PipelineCollectionService
from role_radar.services.pipeline_extraction import PipelineExtractionService
from role_radar.services.pipeline_scoring import PipelineScoringService
from role_radar.worker.checkpoints import recompute_stats


class Pipeline:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        provider: LLMProvider,
        settings: Settings | None = None,
        collector_factory: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings or Settings()
        self._collection = PipelineCollectionService(
            session_factory,
            collector_factory=collector_factory,
            settings=self._settings,
        )
        self._extraction = PipelineExtractionService(session_factory, provider=provider)
        self._scoring = PipelineScoringService(session_factory)

    async def run(self, run_id: str) -> JobSearchRun:
        try:
            with self._session_factory() as session:
                existing = session.get(JobSearchRun, run_id)
                if existing is None:
                    raise LookupError("run not found")
                if existing.status in {
                    JobSearchRunStatus.COMPLETED,
                    JobSearchRunStatus.FAILED,
                    JobSearchRunStatus.CANCELLED,
                }:
                    return existing
            snapshots = self._collection.prepare(run_id)
            for snapshot in snapshots:
                result = await self._collection.execute(snapshot)
                self._collection.finalize(run_id, result)

            with self._session_factory() as session:
                run_after_collection = session.get(JobSearchRun, run_id)
                outcomes = run_after_collection.source_results_json if run_after_collection else {}
            if not snapshots or not outcomes or all(
                result.get("status") != "ok" for result in outcomes.values()
            ):
                return self._fail(run_id, "all_sources_failed")

            self._transition(run_id, JobSearchRunStatus.NORMALIZING)
            job_ids = self._jobs_for_run(run_id)
            self._transition(run_id, JobSearchRunStatus.EXTRACTING)
            for job_id in job_ids:
                try:
                    await self._extract_one(run_id, job_id)
                except RuntimeError as exc:
                    if str(exc) == "request_reconstruction_mismatch":
                        raise
                    self._mark_extraction_failure(run_id, job_id, _safe_code(str(exc)))
                except Exception as exc:
                    self._mark_extraction_failure(run_id, job_id, _safe_code(str(exc)))
            self._transition(run_id, JobSearchRunStatus.SCORING)
            self._scoring.score(run_id, job_ids)
            return self._complete(run_id)
        except Exception as exc:
            return self._fail(run_id, _safe_code(str(exc)) or "pipeline_failed")

    async def _extract_one(self, run_id: str, job_id: str) -> None:
        with self._session_factory() as session:
            row = session.scalar(
                select(RunJob).where(
                    RunJob.run_id == run_id,
                    RunJob.job_id == job_id,
                    RunJob.stage == RunJobStage.EXTRACTED,
                )
            )
            if row is not None and row.status in {RunJobStatus.SUCCEEDED, RunJobStatus.SKIPPED}:
                return
        prepared = self._extraction.prepare(job_id)
        if prepared is None:
            self._mark_extraction_checkpoint(run_id, job_id)
            return
        execution = await self._extraction.execute(prepared)
        finalized = self._extraction.finalize(execution)
        if finalized.retry_corrective:
            prepared = self._extraction.prepare(job_id, corrective=True)
            if prepared is not None:
                finalized = self._extraction.finalize(await self._extraction.execute(prepared))
        with self._session_factory() as session:
            repository = RunRepository(session)
            status = (
                RunJobStatus.SUCCEEDED
                if finalized.status is ExtractionStatus.VALID
                else RunJobStatus.FAILED
            )
            repository.update_run_job(
                run_id=run_id,
                job_id=job_id,
                stage=RunJobStage.EXTRACTED,
                status=status,
                error_code=None if status is RunJobStatus.SUCCEEDED else finalized.status.value,
            )
            session.commit()

    def _mark_extraction_checkpoint(self, run_id: str, job_id: str) -> None:
        with self._session_factory() as session:
            status = session.scalar(
                select(JobExtraction.validation_status)
                .where(JobExtraction.job_id == job_id)
                .order_by(JobExtraction.updated_at.desc())
            )
            repository = RunRepository(session)
            repository.update_run_job(
                run_id=run_id,
                job_id=job_id,
                stage=RunJobStage.EXTRACTED,
                status=(
                    RunJobStatus.SUCCEEDED
                    if status is ExtractionStatus.VALID
                    else RunJobStatus.FAILED
                ),
                error_code=None if status is ExtractionStatus.VALID else "extraction_not_valid",
            )
            session.commit()

    def _mark_extraction_failure(self, run_id: str, job_id: str, error_code: str) -> None:
        with self._session_factory() as session:
            repository = RunRepository(session)
            repository.update_run_job(
                run_id=run_id,
                job_id=job_id,
                stage=RunJobStage.EXTRACTED,
                status=RunJobStatus.FAILED,
                error_code=error_code or "extraction_failed",
            )
            session.commit()

    def _jobs_for_run(self, run_id: str) -> list[str]:
        with self._session_factory() as session:
            return list(
                session.scalars(
                    select(RunJob.job_id)
                    .where(
                        RunJob.run_id == run_id,
                        RunJob.stage == RunJobStage.DEDUPLICATED,
                        RunJob.status == RunJobStatus.SUCCEEDED,
                    )
                    .order_by(RunJob.created_at, RunJob.job_id)
                ).unique()
            )

    def _transition(self, run_id: str, status: JobSearchRunStatus) -> None:
        with self._session_factory() as session:
            RunRepository(session).update_run_status(run_id, status)
            session.commit()

    def _complete(self, run_id: str) -> JobSearchRun:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            jobs = list(session.scalars(select(RunJob).where(RunJob.run_id == run_id)))
            run.stats_json = recompute_stats(run.source_results_json, jobs)
            run.status = JobSearchRunStatus.COMPLETED
            run.completed_at = datetime.now(UTC)
            run.claimed_by = None
            run.lease_expires_at = None
            run.heartbeat_at = None
            session.commit()
            return run

    def _fail(self, run_id: str, error_code: str) -> JobSearchRun:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            jobs = list(session.scalars(select(RunJob).where(RunJob.run_id == run_id)))
            run.stats_json = recompute_stats(run.source_results_json, jobs)
            run.status = JobSearchRunStatus.FAILED
            run.error_code = error_code[:128]
            run.completed_at = datetime.now(UTC)
            run.claimed_by = None
            run.lease_expires_at = None
            run.heartbeat_at = None
            session.commit()
            return run


def _safe_code(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._:-" else "_" for char in value)[:128]
