"""Secuenciador del pipeline; las reglas de cada etapa viven en services."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.broker.protocols import LLMProvider
from role_radar.config import Settings
from role_radar.db.models import (
    JobExtraction,
    JobSearchRun,
    NotificationBatch,
    NotificationItem,
    RunJob,
)
from role_radar.domain.enums import (
    ExtractionStatus,
    JobSearchRunStatus,
    NotificationBatchStatus,
    RunJobStage,
    RunJobStatus,
    SourceType,
)
from role_radar.free_sources.terms import JobicyTermsAcceptance
from role_radar.notifications.contracts import TelegramGateway
from role_radar.notifications.fake import DisabledTelegramGateway
from role_radar.repositories.runs import RunRepository
from role_radar.services.pipeline_collection import PipelineCollectionService
from role_radar.services.pipeline_deep_evaluation import PipelineDeepEvaluationService
from role_radar.services.pipeline_discovery import PipelineDiscoveryService
from role_radar.services.pipeline_extraction import PipelineExtractionService
from role_radar.services.pipeline_free_sources import PipelineFreeSourcesService
from role_radar.services.pipeline_notifications import PipelineNotificationService
from role_radar.services.pipeline_scoring import PipelineScoringService
from role_radar.worker.checkpoints import recompute_stats


class Pipeline:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        provider: LLMProvider,
        deep_provider: LLMProvider | None = None,
        settings: Settings | None = None,
        collector_factory: Any = None,
        notification_gateway: TelegramGateway | None = None,
        notification_recipient: str | None = None,
        discovery_provider: Any = None,
        discovery_collector_factory: Any = None,
        discovery_query_key_secret: bytes | str | None = None,
        free_source_terms: JobicyTermsAcceptance | None = None,
        free_source_collector_factory: Any = None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings or Settings()
        self._collection = PipelineCollectionService(
            session_factory,
            collector_factory=collector_factory,
            settings=self._settings,
        )
        self._discovery = PipelineDiscoveryService(
            session_factory,
            provider=discovery_provider,
            collector_factory=discovery_collector_factory or collector_factory,
            query_key_secret=discovery_query_key_secret,
        )
        self._free_sources = PipelineFreeSourcesService(
            session_factory,
            terms=free_source_terms,
            collector_factory=free_source_collector_factory or collector_factory,
        )
        self._extraction = PipelineExtractionService(session_factory, provider=provider)
        self._scoring = PipelineScoringService(session_factory)
        self._deep = (
            PipelineDeepEvaluationService(
                session_factory, provider=deep_provider, settings=self._settings
            )
            if deep_provider is not None
            else None
        )
        self._notifications = PipelineNotificationService(
            session_factory,
            settings=self._settings,
            gateway=notification_gateway or DisabledTelegramGateway(),
        )
        self._notification_recipient = notification_recipient or "disabled"

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
                resume_deep = existing.status is JobSearchRunStatus.DEEP_EVALUATING
                resume_notify = existing.status is JobSearchRunStatus.NOTIFYING
            if resume_notify:
                await self._notifications.process(
                    run_id, recipient_key=self._notification_recipient
                )
                if self._notification_retry_wait(run_id):
                    return self._release_notification_run(run_id)
                return self._complete(run_id)
            if resume_deep and self._deep is not None:
                await self._deep.process(run_id)
                if self._is_daily_digest(run_id):
                    self._transition(run_id, JobSearchRunStatus.NOTIFYING)
                    await self._notifications.process(
                        run_id, recipient_key=self._notification_recipient
                    )
                    if self._notification_retry_wait(run_id):
                        return self._release_notification_run(run_id)
                return self._complete(run_id)
            snapshots = self._collection.prepare(
                run_id, exclude_source_types=frozenset({SourceType.JOBICY})
            )
            self._collection.start_run_budget()
            free_plan = None
            try:
                free_plan = self._free_sources.prepare(run_id)
            except Exception:
                # Free-source scheduling is an independent producer path.
                free_plan = None
            discovery_finalization = None
            try:
                discovery_plan = self._discovery.prepare(run_id)
                if discovery_plan is not None:
                    discovery_finalization = self._discovery.finalize(
                        await self._discovery.execute(discovery_plan)
                    )
            except Exception:
                # Discovery is advisory; ATS collection continues on any
                # provider, classifier, or discovery persistence failure.
                discovery_finalization = None
            if free_plan is not None:
                for task in free_plan.tasks:
                    try:
                        execution = await self._free_sources.execute(task)
                        self._free_sources.finalize(run_id, execution)
                    except Exception:
                        # A Jobicy outage or persistence error must not remove
                        # ATS/search successes from the same collecting run.
                        continue
            for snapshot in snapshots:
                result = await self._collection.execute(snapshot)
                self._collection.finalize(run_id, result)

            with self._session_factory() as session:
                run_after_collection = session.get(JobSearchRun, run_id)
                outcomes = run_after_collection.source_results_json if run_after_collection else {}
            if not (discovery_finalization and discovery_finalization.producer_success) and (
                not snapshots
                or not outcomes
                or all(
                    result.get("status") not in {"ok", "partial"}
                    for result in outcomes.values()
                )
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
            if self._deep is not None:
                self._deep.prepare_queue(run_id, job_ids)
                self._transition(run_id, JobSearchRunStatus.DEEP_EVALUATING)
                await self._deep.process(run_id)
            if self._is_daily_digest(run_id):
                self._transition(run_id, JobSearchRunStatus.NOTIFYING)
                await self._notifications.process(
                    run_id, recipient_key=self._notification_recipient
                )
                if self._notification_retry_wait(run_id):
                    return self._release_notification_run(run_id)
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
            stats = recompute_stats(run.source_results_json, jobs)
            batches = list(
                session.scalars(select(NotificationBatch).where(NotificationBatch.run_id == run_id))
            )
            items = list(
                session.scalars(select(NotificationItem).where(NotificationItem.run_id == run_id))
            )
            stats.update(
                digests_sent=sum(batch.status.value == "sent" for batch in batches),
                digests_failed=sum(batch.status.value == "failed" for batch in batches),
                digests_unknown=sum(batch.status.value == "unknown" for batch in batches),
                notified_jobs=sum(item.status.value == "sent" for item in items),
                notification_failed=sum(item.status.value == "failed" for item in items),
                notification_unknown=sum(item.status.value == "unknown" for item in items),
                notification_skipped=sum(
                    job.status is RunJobStatus.SKIPPED
                    for job in jobs
                    if job.stage is RunJobStage.NOTIFIED
                ),
            )
            run.stats_json = stats
            run.status = JobSearchRunStatus.COMPLETED
            run.completed_at = datetime.now(UTC)
            run.claimed_by = None
            run.lease_expires_at = None
            run.heartbeat_at = None
            session.commit()
            return run

    def _is_daily_digest(self, run_id: str) -> bool:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            return (
                run is not None
                and getattr(run.notification_mode, "value", run.notification_mode) == "daily_digest"
            )

    def _notification_retry_wait(self, run_id: str) -> bool:
        with self._session_factory() as session:
            status = session.scalar(
                select(NotificationBatch.status)
                .where(NotificationBatch.run_id == run_id)
                .order_by(NotificationBatch.updated_at.desc())
                .limit(1)
            )
            return status in {
                NotificationBatchStatus.RETRY_WAIT,
                NotificationBatchStatus.SENDING,
            }

    def _release_notification_run(self, run_id: str) -> JobSearchRun:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
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
