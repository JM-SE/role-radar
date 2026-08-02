"""Durable item reservation and outcome helpers."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import NotificationItem
from role_radar.domain.enums import NotificationItemStatus


class NotificationItemRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def globally_reserved(self, *, channel: str, recipient_key_hash: str, job_id: str) -> bool:
        return (
            self._session.scalar(
                select(NotificationItem.id).where(
                    NotificationItem.channel == channel,
                    NotificationItem.recipient_key_hash == recipient_key_hash,
                    NotificationItem.job_id == job_id,
                )
            )
            is not None
        )

    def list_for_batch(self, batch_id: str) -> list[NotificationItem]:
        return list(
            self._session.scalars(
                select(NotificationItem)
                .where(NotificationItem.batch_id == batch_id)
                .order_by(NotificationItem.rank)
            )
        )

    def apply_outcome(
        self, batch_id: str, status: NotificationItemStatus, code: str | None = None
    ) -> None:
        for item in self.list_for_batch(batch_id):
            item.status = status
            item.outcome_code = code[:128] if code else None
            item.sent_at = datetime.now(UTC) if status is NotificationItemStatus.SENT else None
        self._session.flush()
