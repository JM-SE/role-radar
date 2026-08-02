"""CAS lifecycle and stale recovery for notification batches."""

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from role_radar.db.models import NotificationBatch, NotificationItem
from role_radar.domain.enums import NotificationBatchStatus, NotificationItemStatus


class NotificationBatchRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_operation(self, operation_key: str) -> NotificationBatch | None:
        return self._session.scalar(
            select(NotificationBatch).where(NotificationBatch.operation_key == operation_key)
        )

    def get(self, batch_id: str) -> NotificationBatch | None:
        return self._session.get(NotificationBatch, batch_id)

    def claim_sending(
        self, batch_id: str, *, max_attempts: int, now: datetime | None = None
    ) -> NotificationBatch | None:
        current = now or datetime.now(UTC)
        result = self._session.execute(
            update(NotificationBatch)
            .where(
                NotificationBatch.id == batch_id,
                NotificationBatch.status.in_(
                    (NotificationBatchStatus.PREPARED, NotificationBatchStatus.RETRY_WAIT)
                ),
                NotificationBatch.attempt_count < max_attempts,
                (
                    NotificationBatch.next_attempt_at.is_(None)
                    | (NotificationBatch.next_attempt_at <= current)
                ),
            )
            .values(
                status=NotificationBatchStatus.SENDING,
                attempt_count=NotificationBatch.attempt_count + 1,
                sending_started_at=current,
                next_attempt_at=None,
                updated_at=current,
            )
        )
        if int(cast(Any, result).rowcount) != 1:
            return None
        self._session.flush()
        return self.get(batch_id)

    def recover_stale(self, *, older_than: timedelta, now: datetime | None = None) -> int:
        current = now or datetime.now(UTC)
        stale_ids = select(NotificationBatch.id).where(
            NotificationBatch.status == NotificationBatchStatus.SENDING,
            NotificationBatch.sending_started_at <= current - older_than,
        )
        self._session.execute(
            update(NotificationItem)
            .where(NotificationItem.batch_id.in_(stale_ids))
            .values(status=NotificationItemStatus.UNKNOWN, outcome_code="stale_sending")
        )
        result = self._session.execute(
            update(NotificationBatch)
            .where(
                NotificationBatch.status == NotificationBatchStatus.SENDING,
                NotificationBatch.sending_started_at <= current - older_than,
            )
            .values(
                status=NotificationBatchStatus.UNKNOWN,
                error_code="stale_sending",
                body=None,
                updated_at=current,
            )
        )
        count = int(cast(Any, result).rowcount)
        return count

    def finalize(
        self,
        batch_id: str,
        *,
        attempt_count: int,
        status: NotificationBatchStatus,
        error_code: str | None = None,
        response_status: int | None = None,
        message_id: int | None = None,
        next_attempt_at: datetime | None = None,
    ) -> NotificationBatch | None:
        batch = self.get(batch_id)
        if (
            batch is None
            or batch.status is not NotificationBatchStatus.SENDING
            or batch.attempt_count != attempt_count
        ):
            return batch
        batch.status = status
        batch.error_code = error_code[:128] if error_code else None
        batch.response_status = response_status
        batch.telegram_message_id = message_id if status is NotificationBatchStatus.SENT else None
        batch.sent_at = datetime.now(UTC) if status is NotificationBatchStatus.SENT else None
        batch.next_attempt_at = next_attempt_at
        if status in {
            NotificationBatchStatus.SENT,
            NotificationBatchStatus.FAILED,
            NotificationBatchStatus.UNKNOWN,
        }:
            batch.body = None
        self._session.flush()
        return batch
