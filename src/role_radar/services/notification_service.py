"""Transactional multipart outbox preparation and at-most-once Telegram delivery."""

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
from role_radar.notifications.formatter import (
    ALERT_FORMATTER_VERSION,
    FORMATTER_VERSION,
    LEGACY_DIGEST_FORMATTER_VERSION,
    format_digest_batches,
    utf16_units,
)
from role_radar.notifications.selection import select_delivery_candidates
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
    ) -> tuple[NotificationBatch, ...]:
        """Reserve every rendered delivery part atomically, without external I/O."""
        recipient_hash = recipient_key_hash(recipient_key)
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            slot = schedule_slot or run.schedule_slot or "manual"
            mode = getattr(run.notification_mode, "value", run.notification_mode)
            formatter_version = (
                ALERT_FORMATTER_VERSION
                if mode == "match_alerts"
                else FORMATTER_VERSION
            )
            prefix = f"{run_id}:{slot}:telegram:{recipient_hash}:{formatter_version}:part:"
            existing = tuple(
                session.scalars(
                    select(NotificationBatch)
                    .where(NotificationBatch.operation_key.startswith(prefix))
                    .order_by(NotificationBatch.operation_key)
                )
            )
            legacy_operation_key = f"{run_id}:{slot}:telegram:{recipient_hash}:{formatter_version}"
            legacy = session.scalar(
                select(NotificationBatch).where(
                    NotificationBatch.operation_key == legacy_operation_key
                )
            )
            legacy_v1 = None
            if mode == "daily_digest":
                legacy_v1_key = (
                    f"{run_id}:{slot}:telegram:{recipient_hash}:"
                    f"{LEGACY_DIGEST_FORMATTER_VERSION}"
                )
                legacy_v1 = session.scalar(
                    select(NotificationBatch).where(
                        NotificationBatch.operation_key == legacy_v1_key
                    )
                )
                if legacy_v1 is not None:
                    session.expunge(legacy_v1)
            if existing:
                for batch in existing:
                    session.expunge(batch)
                return existing
            if legacy is not None:
                session.expunge(legacy)
                return (legacy,)
            if legacy_v1 is not None:
                return (legacy_v1,)
            if mode not in {"match_alerts", "daily_digest"}:
                session.commit()
                return ()
            if getattr(run.status, "value", run.status) != "notifying":
                raise ValueError("notification_run_not_ready")
            candidates = JobRepository(session).list_delivery_candidates(
                run_id=run_id, channel="telegram", recipient_key_hash=recipient_hash
            )
            selection = select_delivery_candidates(candidates)
            for job_id, reason in selection.exclusions:
                _mark_run_job(session, run_id, job_id, RunJobStatus.SKIPPED, reason)
            if not selection.selected:
                _mark_run_jobs_skipped(session, run_id, "no_delivery_candidates")
                session.commit()
                return ()
            formatted = format_digest_batches(
                selection.selected,
                max_units=self._settings.telegram_message_max_units,
                heading=(
                    "New Role Radar matches"
                    if mode == "match_alerts"
                    else "Daily digest"
                ),
            )
            prepared: list[NotificationBatch] = []
            try:
                for ordinal, part in enumerate(formatted, 1):
                    batch = NotificationBatch(
                        run_id=run_id,
                        schedule_slot=slot,
                        channel="telegram",
                        recipient_key_hash=recipient_hash,
                        operation_key=f"{prefix}{ordinal:04d}",
                        fingerprint=part.body_hash,
                        formatter_version=formatter_version,
                        status=NotificationBatchStatus.PREPARED,
                        body=part.body,
                        body_hash=part.body_hash,
                        body_length=utf16_units(part.body),
                        item_count=len(part.candidates),
                    )
                    session.add(batch)
                    session.flush()
                    for rank, candidate in enumerate(part.candidates, 1):
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
                    prepared.append(batch)
                session.commit()
                for batch in prepared:
                    session.refresh(batch)
                    session.expunge(batch)
            except IntegrityError:
                session.rollback()
                existing = tuple(
                    session.scalars(
                        select(NotificationBatch)
                        .where(NotificationBatch.operation_key.startswith(prefix))
                        .order_by(NotificationBatch.operation_key)
                    )
                )
                if existing:
                    for batch in existing:
                        session.expunge(batch)
                    return existing
                raise
            return tuple(prepared)

    async def deliver(self, batch_id: str, gateway: TelegramGateway) -> NotificationBatch | None:
        with self._session_factory() as session:
            repo = NotificationBatchRepository(session)
            batch = repo.claim_sending(batch_id, max_attempts=self._settings.telegram_max_attempts)
            if batch is None:
                session.commit()
                detached = repo.get(batch_id)
                if detached is not None:
                    session.refresh(detached)
                    session.expunge(detached)
                return detached
            attempt, body = batch.attempt_count, batch.body
            session.commit()
        if body is None:
            with self._session_factory() as session:
                detached = session.get(NotificationBatch, batch_id)
                if detached is not None:
                    session.refresh(detached)
                    session.expunge(detached)
                return detached
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
                terminal = (
                    RunJobStatus.SUCCEEDED
                    if final.status is NotificationBatchStatus.SENT
                    else RunJobStatus.FAILED
                )
                for item in NotificationItemRepository(session).list_for_batch(batch_id):
                    _mark_run_job(
                        session,
                        final.run_id,
                        item.job_id,
                        terminal,
                        "delivery_unknown"
                        if final.status is NotificationBatchStatus.UNKNOWN
                        else None,
                    )
            session.commit()
            if final is not None:
                session.refresh(final)
                session.expunge(final)
            return final

    async def process(
        self, run_id: str, *, recipient_key: str, gateway: TelegramGateway
    ) -> tuple[NotificationBatch, ...]:
        with self._session_factory() as session:
            NotificationBatchRepository(session).recover_stale(
                older_than=timedelta(seconds=self._settings.worker_lease_duration_seconds)
            )
            session.commit()
        prepared = self.prepare(run_id, recipient_key=recipient_key)
        output: list[NotificationBatch] = []
        for batch in prepared:
            final = await self.deliver(batch.id, gateway)
            if final is None:
                continue
            output.append(final)
            if final.status in {
                NotificationBatchStatus.RETRY_WAIT,
                NotificationBatchStatus.SENDING,
            }:
                break
        return tuple(output)


def recipient_key_hash(recipient_key: str) -> str:
    return hashlib.sha256(recipient_key.encode("utf-8")).hexdigest()


def _mark_run_job(
    session: Session, run_id: str, job_id: str, status: RunJobStatus, error_code: str | None = None
) -> None:
    row = session.scalar(
        select(RunJob).where(
            RunJob.run_id == run_id, RunJob.job_id == job_id, RunJob.stage == RunJobStage.NOTIFIED
        )
    )
    if row is None:
        row = RunJob(
            run_id=run_id,
            job_id=job_id,
            stage=RunJobStage.NOTIFIED,
            status=status,
            error_code=error_code,
        )
        session.add(row)
    else:
        row.status, row.error_code = status, error_code


def _mark_run_jobs_skipped(session: Session, run_id: str, reason: str) -> None:
    for job_id in session.scalars(
        select(RunJob.job_id).where(
            RunJob.run_id == run_id,
            RunJob.stage == RunJobStage.SCORED,
            RunJob.status == RunJobStatus.SUCCEEDED,
        )
    ):
        _mark_run_job(session, run_id, job_id, RunJobStatus.SKIPPED, reason)
