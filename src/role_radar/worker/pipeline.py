"""Secuenciador del pipeline; las reglas de cada etapa viven en services."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.broker.protocols import LLMProvider
from role_radar.config import Settings
from role_radar.db.models import (
    DiscoveryCycle,
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
from role_radar.execution_budget import (
    CANARY_BUDGET,
    CanaryAmbiguousAttempt,
    CanaryDeferred,
    CanaryExecutionBudget,
    activate_canary_budget,
    reset_canary_budget,
    validate_canary_checkpoint,
)
from role_radar.free_sources.terms import JobicyTermsAcceptance
from role_radar.notifications.contracts import TelegramGateway
from role_radar.notifications.fake import DisabledTelegramGateway
from role_radar.repositories.runs import RunRepository
from role_radar.services.eligibility_reprocessing import (
    MANIFEST_KEY,
    EligibilityReprocessingService,
)
from role_radar.services.pipeline_collection import PipelineCollectionService
from role_radar.services.pipeline_deep_evaluation import PipelineDeepEvaluationService
from role_radar.services.pipeline_discovery import PipelineDiscoveryService
from role_radar.services.pipeline_extraction import PipelineExtractionService
from role_radar.services.pipeline_free_sources import PipelineFreeSourcesService
from role_radar.services.pipeline_mailbox import PipelineMailboxService
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
        discovery_policy_v1: Any | None = None,
        free_source_terms: JobicyTermsAcceptance | None = None,
        free_source_collector_factory: Any = None,
        mailbox_provider_factory: Any = None,
        mailbox_url_hmac_key: bytes | None = None,
        mailbox_content_hmac_key: bytes | None = None,
        mailbox_hmac_keys: dict[str, tuple[bytes, bytes]] | None = None,
        mailbox_descriptor_resolver: Any = None,
        mailbox_credential_resolver: Any = None,
        mailbox_imap_session_factory: Any = None,
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
            discovery_policy_v1=discovery_policy_v1,
        )
        self._free_sources = PipelineFreeSourcesService(
            session_factory,
            terms=free_source_terms,
            collector_factory=free_source_collector_factory or collector_factory,
        )
        self._mailbox = PipelineMailboxService(
            session_factory,
            provider_factory=mailbox_provider_factory,
            url_hmac_key=mailbox_url_hmac_key,
            content_hmac_key=mailbox_content_hmac_key,
            mailbox_hmac_keys=mailbox_hmac_keys,
            descriptor_resolver=mailbox_descriptor_resolver,
            credential_resolver=mailbox_credential_resolver,
            imap_session_factory=mailbox_imap_session_factory,
        )
        self._extraction = PipelineExtractionService(session_factory, provider=provider)
        self._scoring = PipelineScoringService(session_factory)
        self._eligibility = EligibilityReprocessingService(session_factory, self._extraction)
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
        budget_token = None
        is_canary = False
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
                is_canary = existing.canary_budget_json is not None
                if is_canary and existing.canary_budget_json != CANARY_BUDGET:
                    raise CanaryAmbiguousAttempt("canary_budget_missing_or_changed")
                canary_stage = (
                    validate_canary_checkpoint(existing.canary_checkpoint_json)[0]
                    if is_canary
                    else "discovery"
                )
            if is_canary:
                budget_token = activate_canary_budget(
                    CanaryExecutionBudget(self._session_factory, run_id)
                )
            if resume_notify:
                await self._notifications.process(
                    run_id, recipient_key=self._notification_recipient
                )
                if self._notification_retry_wait(run_id):
                    return self._release_notification_run(run_id)
                if is_canary:
                    self._checkpoint_canary(run_id, stage="complete", cursor=0)
                return self._complete(run_id)
            if resume_deep and self._deep is not None:
                await self._deep.process(run_id)
                if self._is_notification_enabled(run_id):
                    self._transition(run_id, JobSearchRunStatus.NOTIFYING)
                    await self._notifications.process(
                        run_id, recipient_key=self._notification_recipient
                    )
                    if self._notification_retry_wait(run_id):
                        return self._release_notification_run(run_id)
                if is_canary:
                    self._checkpoint_canary(run_id, stage="complete", cursor=0)
                return self._complete(run_id)
            manifest = await self._eligibility.process(run_id)
            if not manifest["complete"]:
                raise RuntimeError("product_eligibility_reprocessing_pending")
            snapshots = (
                ()
                if is_canary
                else self._collection.prepare(
                    run_id, exclude_source_types=frozenset({SourceType.JOBICY})
                )
            )
            if not is_canary:
                self._collection.start_run_budget()
            free_plan = None
            if not is_canary:
                try:
                    free_plan = self._free_sources.prepare(run_id)
                except Exception:
                    # Free-source scheduling is an independent producer path.
                    free_plan = None
            discovery_finalization = None
            try:
                discovery_plan = (
                    self._discovery.prepare(run_id)
                    if not is_canary or canary_stage == "discovery"
                    else None
                )
                if discovery_plan is not None:
                    discovery_finalization = self._discovery.finalize(
                        await self._discovery.execute(discovery_plan)
                    )
            except (CanaryAmbiguousAttempt, CanaryDeferred):
                raise
            except Exception:
                # Discovery is advisory; ATS collection continues on any
                # provider, classifier, or discovery persistence failure.
                discovery_finalization = None
            if is_canary and canary_stage == "discovery":
                if discovery_finalization is None or discovery_finalization.status == "degraded":
                    raise CanaryDeferred("canary_discovery_incomplete")
                with self._session_factory() as session:
                    cycle = session.get(DiscoveryCycle, discovery_finalization.cycle_id)
                    stats = cycle.stats_json if cycle is not None else {}
                    if stats.get("known", 0) and not stats.get("verified_jobs", 0):
                        raise CanaryDeferred("canary_greenhouse_verification_incomplete")
            if free_plan is not None:
                for task in free_plan.tasks:
                    try:
                        execution = await self._free_sources.execute(task)
                        self._free_sources.finalize(run_id, execution)
                    except Exception:
                        # A Jobicy outage or persistence error must not remove
                        # ATS/search successes from the same collecting run.
                        continue
            if not is_canary:
                try:
                    mailbox_plan = self._mailbox.prepare(run_id)
                    mailbox_execution = await self._mailbox.execute(mailbox_plan)
                    self._mailbox.finalize(mailbox_execution)
                except Exception:
                    # Mailbox is an independent, degradable producer.  A missing
                    # worker credential or IMAP outage must not suppress ATS/feed.
                    pass
            for snapshot in snapshots:
                result = await self._collection.execute(snapshot)
                self._collection.finalize(run_id, result)

            with self._session_factory() as session:
                run_after_collection = session.get(JobSearchRun, run_id)
                outcomes = run_after_collection.source_results_json if run_after_collection else {}
            if (
                not is_canary
                and not (discovery_finalization and discovery_finalization.producer_success)
                and (
                    not snapshots
                    or not outcomes
                    or all(
                        result.get("status") not in {"ok", "partial"}
                        for result in outcomes.values()
                    )
                )
            ):
                return self._fail(run_id, "all_sources_failed")

            resume_after_extraction = is_canary and canary_stage in {
                "scoring",
                "deep_evaluation",
                "notifications",
                "complete",
            }
            resume_after_scoring = is_canary and canary_stage in {
                "deep_evaluation",
                "notifications",
                "complete",
            }
            resume_after_deep = is_canary and canary_stage in {"notifications", "complete"}
            resume_after_notifications = is_canary and canary_stage == "complete"
            job_ids = self._jobs_for_run(run_id)
            if not resume_after_extraction:
                if is_canary and canary_stage != "extraction":
                    self._checkpoint_canary(run_id, stage="extraction", cursor=0)
                self._transition(run_id, JobSearchRunStatus.NORMALIZING)
                self._transition(run_id, JobSearchRunStatus.EXTRACTING)
                start_cursor = 0
                if is_canary and canary_stage == "extraction":
                    with self._session_factory() as session:
                        resumed = session.get(JobSearchRun, run_id)
                        if resumed is None:
                            raise CanaryAmbiguousAttempt("canary_run_missing")
                        start_cursor = (resumed.canary_checkpoint_json or {}).get("cursor", 0)
                    if (
                        not isinstance(start_cursor, int)
                        or isinstance(start_cursor, bool)
                        or start_cursor < 0
                        or start_cursor > len(job_ids)
                    ):
                        raise CanaryAmbiguousAttempt("canary_checkpoint_cursor_invalid")
                for cursor, job_id in enumerate(job_ids[start_cursor:], start_cursor):
                    if is_canary:
                        self._checkpoint_canary(run_id, stage="extraction", cursor=cursor)
                    try:
                        await self._extract_one(run_id, job_id)
                    except (CanaryAmbiguousAttempt, CanaryDeferred):
                        raise
                    except RuntimeError as exc:
                        if str(exc) == "request_reconstruction_mismatch":
                            raise
                        self._mark_extraction_failure(run_id, job_id, _safe_code(str(exc)))
                    except Exception as exc:
                        self._mark_extraction_failure(run_id, job_id, _safe_code(str(exc)))
            if not resume_after_scoring:
                if is_canary and canary_stage != "scoring":
                    self._checkpoint_canary(run_id, stage="scoring", cursor=0)
                self._transition(run_id, JobSearchRunStatus.SCORING)
                self._scoring.score(run_id, job_ids)
            if self._deep is not None and not resume_after_deep:
                if is_canary and canary_stage != "deep_evaluation":
                    self._deep.prepare_queue(run_id, job_ids)
                self._transition(run_id, JobSearchRunStatus.DEEP_EVALUATING)
                if is_canary and canary_stage != "deep_evaluation":
                    self._checkpoint_canary(run_id, stage="deep_evaluation", cursor=0)
                await self._deep.process(run_id)
            if not resume_after_notifications and self._is_notification_enabled(run_id):
                if is_canary and canary_stage != "notifications":
                    self._checkpoint_canary(run_id, stage="notifications", cursor=0)
                self._transition(run_id, JobSearchRunStatus.NOTIFYING)
                await self._notifications.process(
                    run_id, recipient_key=self._notification_recipient
                )
                if self._notification_retry_wait(run_id):
                    return self._release_notification_run(run_id)
            if is_canary:
                self._checkpoint_canary(run_id, stage="complete", cursor=0)
            return self._complete(run_id)
        except (CanaryDeferred, CanaryAmbiguousAttempt) as exc:
            return self._defer_canary(run_id, _safe_code(str(exc)) or "canary_deferred")
        except Exception as exc:
            return self._fail(run_id, _safe_code(str(exc)) or "pipeline_failed")
        finally:
            if budget_token is not None:
                reset_canary_budget(budget_token)

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

    def _defer_canary(self, run_id: str, error_code: str) -> JobSearchRun:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            if run.canary_budget_json is None:
                return self._fail(run_id, error_code)
            run.status = JobSearchRunStatus.DEFERRED
            run.error_code = error_code[:128]
            run.claimed_by = None
            run.lease_expires_at = None
            run.heartbeat_at = None
            session.commit()
            return run

    def _checkpoint_canary(self, run_id: str, *, stage: str, cursor: int) -> None:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None or run.canary_budget_json is None:
                return
            checkpoint = dict(run.canary_checkpoint_json or {})
            checkpoint.update(version=1, stage=stage, cursor=cursor)
            checkpoint.setdefault("counts", {})
            checkpoint.setdefault("reservations", [])
            run.canary_checkpoint_json = checkpoint
            session.commit()

    def _transition(self, run_id: str, status: JobSearchRunStatus) -> None:
        with self._session_factory() as session:
            RunRepository(session).update_run_status(run_id, status)
            session.commit()

    def _complete(self, run_id: str) -> JobSearchRun:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            checkpoint = run.canary_checkpoint_json or {}
            if run.canary_budget_json is not None and (
                checkpoint.get("reservations") or checkpoint.get("logical_reservations")
            ):
                raise CanaryAmbiguousAttempt("canary_side_effect_unresolved")
            jobs = list(session.scalars(select(RunJob).where(RunJob.run_id == run_id)))
            eligibility = (run.stats_json or {}).get(MANIFEST_KEY)
            stats = recompute_stats(run.source_results_json, jobs)
            if eligibility is not None:
                stats[MANIFEST_KEY] = eligibility
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
            from role_radar.services.source_activation import SourceActivationCampaignService
            SourceActivationCampaignService(session).finalize_run(run_id)
            session.commit()
            return run

    def _is_notification_enabled(self, run_id: str) -> bool:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            return (
                run is not None
                and getattr(run.notification_mode, "value", run.notification_mode)
                in {"daily_digest", "match_alerts"}
            )

    def _notification_retry_wait(self, run_id: str) -> bool:
        with self._session_factory() as session:
            return session.scalar(
                select(NotificationBatch.id)
                .where(
                    NotificationBatch.run_id == run_id,
                    NotificationBatch.status.in_(
                        (NotificationBatchStatus.RETRY_WAIT, NotificationBatchStatus.SENDING)
                    ),
                )
                .limit(1)
            ) is not None

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
            stats = recompute_stats(run.source_results_json, jobs)
            manifest = (run.stats_json or {}).get(MANIFEST_KEY)
            if manifest is not None:
                    stats[MANIFEST_KEY] = manifest
            run.stats_json = stats
            run.status = JobSearchRunStatus.FAILED
            run.error_code = error_code[:128]
            run.completed_at = datetime.now(UTC)
            run.claimed_by = None
            run.lease_expires_at = None
            run.heartbeat_at = None
            from role_radar.services.source_activation import SourceActivationCampaignService
            SourceActivationCampaignService(session).finalize_run(run_id)
            session.commit()
            return run


def _safe_code(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._:-" else "_" for char in value)[:128]
