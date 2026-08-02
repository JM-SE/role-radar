"""Transactional outbox preparation and at-most-once Telegram delivery."""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.config import Settings
from role_radar.db.models import JobSearchRun, NotificationBatch, NotificationItem, RunJob
from role_radar.domain.enums import (
    NotificationBatchStatus,
    NotificationItemStatus,
    RunJobStage,
    RunJobStatus,
)
from role_radar.notifications.contracts import (
    Accepted,
    DefinitePreSendFailure,
    Indeterminate,
    PermanentFailure,
    RateLimited,
    TelegramGateway,
    TelegramSendRequest,
)
from role_radar.notifications.formatter import FORMATTER_VERSION, format_digest, utf16_units
from role_radar.notifications.selection import select_top_digest
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.notification_batches import NotificationBatchRepository
from role_radar.repositories.notification_items import NotificationItemRepository


class NotificationService:
    def __init__(
        self, session_factory: Callable[[], Session], *, settings: Settings | None = None
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings or Settings()

    def prepare(
        self, run_id: str, *, recipient_key: str, schedule_slot: str | None = None
    ) -> NotificationBatch | None:
        """Reserve and render in one DB transaction, without external I/O."""
        recipient_hash = recipient_key_hash(recipient_key)
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            slot = schedule_slot or run.schedule_slot or "manual"
            operation_key = f"{run_id}:{slot}:telegram:{recipient_hash}:{FORMATTER_VERSION}"
            batches = NotificationBatchRepository(session)
            existing = batches.get_by_operation(operation_key)
            if existing is not None:
                return existing
            candidates = JobRepository(session).list_digest_candidates(
                run_id=run_id, channel="telegram", recipient_key_hash=recipient_hash
            )
            selected = select_top_digest(candidates).selected
            formatted = format_digest(selected, max_units=self._settings.telegram_message_max_units)
            if formatted is None:
                _mark_run_jobs_skipped(session, run_id, "no_digest_candidates")
                session.commit()
                return None
            batch = NotificationBatch(
                run_id=run_id,
                schedule_slot=slot,
                channel="telegram",
                recipient_key_hash=recipient_hash,
                operation_key=operation_key,
                fingerprint=formatted.body_hash,
                formatter_version=FORMATTER_VERSION,
                status=NotificationBatchStatus.PREPARED,
                body=formatted.body,
                body_hash=formatted.body_hash,
                body_length=utf16_units(formatted.body),
                item_count=len(formatted.candidates),
            )
            session.add(batch)
            session.flush()
            for rank, candidate in enumerate(formatted.candidates, 1):
                session.add(
                    NotificationItem(
                        batch_id=batch.id,
                        run_id=run_id,
                        channel="telegram",
                        recipient_key_hash=recipient_hash,
                        job_id=candidate.job_id,
                        job_score_id=candidate.job_score_id,
                        deep_evaluation_id=candidate.deep_evaluation_id,
                        rank=rank,
                    )
                )
                _mark_run_job(session, run_id, candidate.job_id, RunJobStatus.PENDING)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = batches.get_by_operation(operation_key)
                if existing is not None:
                    return existing
                raise
            return batch

    async def deliver(self, batch_id: str, gateway: TelegramGateway) -> NotificationBatch | None:
        with self._session_factory() as session:
            repo = NotificationBatchRepository(session)
            batch = repo.claim_sending(batch_id, max_attempts=self._settings.telegram_max_attempts)
            if batch is None:
                session.commit()
                return repo.get(batch_id)
            attempt = batch.attempt_count
            body = batch.body
            if body is None:
                session.commit()
                return batch
            session.commit()
        result = await gateway.send_message(TelegramSendRequest(body=body))
        with self._session_factory() as session:
            repo = NotificationBatchRepository(session)
            if isinstance(result, Accepted):
                final = repo.finalize(
                    batch_id,
                    attempt_count=attempt,
                    status=NotificationBatchStatus.SENT,
                    message_id=result.message_id,
                )
                NotificationItemRepository(session).apply_outcome(
                    batch_id, NotificationItemStatus.SENT
                )
            elif isinstance(result, RateLimited) and attempt < self._settings.telegram_max_attempts:
                final = repo.finalize(
                    batch_id,
                    attempt_count=attempt,
                    status=NotificationBatchStatus.RETRY_WAIT,
                    error_code="rate_limited",
                    next_attempt_at=datetime.now(UTC)
                    + timedelta(
                        seconds=min(
                            result.retry_after, self._settings.telegram_retry_after_max_seconds
                        )
                    ),
                )
            elif (
                isinstance(result, DefinitePreSendFailure)
                and attempt < self._settings.telegram_max_attempts
            ):
                final = repo.finalize(
                    batch_id,
                    attempt_count=attempt,
                    status=NotificationBatchStatus.RETRY_WAIT,
                    error_code=result.code,
                    next_attempt_at=datetime.now(UTC)
                    + timedelta(seconds=self._settings.worker_retry_base_seconds),
                )
            elif isinstance(result, PermanentFailure):
                final = repo.finalize(
                    batch_id,
                    attempt_count=attempt,
                    status=NotificationBatchStatus.FAILED,
                    error_code=result.code,
                    response_status=result.status,
                )
                NotificationItemRepository(session).apply_outcome(
                    batch_id, NotificationItemStatus.FAILED, result.code
                )
            else:
                code = result.code if isinstance(result, Indeterminate) else "delivery_failed"
                final = repo.finalize(
                    batch_id,
                    attempt_count=attempt,
                    status=NotificationBatchStatus.UNKNOWN,
                    error_code=code,
                    response_status=getattr(result, "status", None),
                )
                NotificationItemRepository(session).apply_outcome(
                    batch_id, NotificationItemStatus.UNKNOWN, code
                )
            if final is not None and final.status in {
                NotificationBatchStatus.SENT,
                NotificationBatchStatus.FAILED,
                NotificationBatchStatus.UNKNOWN,
            }:
                item_status = {
                    NotificationBatchStatus.SENT: RunJobStatus.SUCCEEDED,
                    NotificationBatchStatus.FAILED: RunJobStatus.FAILED,
                    NotificationBatchStatus.UNKNOWN: RunJobStatus.FAILED,
                }[final.status]
                for item in NotificationItemRepository(session).list_for_batch(batch_id):
                    _mark_run_job(session, final.run_id, item.job_id, item_status)
                    row = session.scalar(
                        select(RunJob).where(
                            RunJob.run_id == final.run_id,
                            RunJob.job_id == item.job_id,
                            RunJob.stage == RunJobStage.NOTIFIED,
                        )
                    )
                    if row is not None and final.status is NotificationBatchStatus.UNKNOWN:
                        row.error_code = "delivery_unknown"
            session.commit()
            return final

    async def process(
        self, run_id: str, *, recipient_key: str, gateway: TelegramGateway
    ) -> NotificationBatch | None:
        with self._session_factory() as session:
            NotificationBatchRepository(session).recover_stale(
                older_than=timedelta(seconds=self._settings.worker_lease_duration_seconds)
            )
            session.commit()
        batch = self.prepare(run_id, recipient_key=recipient_key)
        if batch is None:
            return None
        return await self.deliver(batch.id, gateway)


def recipient_key_hash(recipient_key: str) -> str:
    return hashlib.sha256(recipient_key.encode("utf-8")).hexdigest()


def _mark_run_job(session: Session, run_id: str, job_id: str, status: RunJobStatus) -> None:
    row = session.scalar(
        select(RunJob).where(
            RunJob.run_id == run_id, RunJob.job_id == job_id, RunJob.stage == RunJobStage.NOTIFIED
        )
    )
    if row is None:
        row = RunJob(run_id=run_id, job_id=job_id, stage=RunJobStage.NOTIFIED, status=status)
        session.add(row)
    elif row.status not in {RunJobStatus.SUCCEEDED, RunJobStatus.FAILED, RunJobStatus.SKIPPED}:
        row.status = status


def _mark_run_jobs_skipped(session: Session, run_id: str, reason: str) -> None:
    for job_id in session.scalars(
        select(RunJob.job_id).where(RunJob.run_id == run_id, RunJob.stage == RunJobStage.SCORED)
    ).all():
        _mark_run_job(session, run_id, job_id, RunJobStatus.SKIPPED)
        row = session.scalar(
            select(RunJob).where(
                RunJob.run_id == run_id,
                RunJob.job_id == job_id,
                RunJob.stage == RunJobStage.NOTIFIED,
            )
        )
        if row is not None:
            row.error_code = reason
