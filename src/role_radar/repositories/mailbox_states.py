"""Short DB-only operations for mailbox cursor state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import MailboxState

MAILBOX_CADENCE = timedelta(hours=1)


class MailboxStateRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, source_id: str) -> MailboxState | None:
        return self._session.scalar(select(MailboxState).where(MailboxState.source_id == source_id))

    def ensure(self, source_id: str, *, now: datetime) -> MailboxState:
        row = self.get(source_id)
        if row is not None:
            return row
        current = _utc(now)
        row = MailboxState(
            id=str(uuid4()),
            source_id=source_id,
            next_due_at=current,
            created_at=current,
            updated_at=current,
        )
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
        except IntegrityError:
            existing = self.get(source_id)
            if existing is None:
                raise
            return existing
        return row

    def reserve(self, source_id: str, *, run_id: str, now: datetime) -> MailboxState | None:
        current = _utc(now)
        row = self.ensure(source_id, now=current)
        if (
            row.operation_id is not None
            and row.operation_id.startswith("mailbox:")
            and row.last_request_at is None
            and row.last_reserved_slot is not None
            and row.last_reserved_slot <= current < _utc(row.next_due_at)
        ):
            return row
        next_due = _utc(row.next_due_at)
        if row.last_reserved_slot is not None and row.last_reserved_slot <= current < next_due:
            return None
        slot = max(current, next_due)
        result = self._session.execute(
            update(MailboxState)
            .where(MailboxState.source_id == source_id, MailboxState.revision == row.revision)
            .values(
                last_reserved_slot=slot,
                next_due_at=slot + MAILBOX_CADENCE,
                reservation_id=str(uuid4()),
                operation_id=f"mailbox:{run_id}:{source_id}",
                last_error_code=None,
                revision=MailboxState.revision + 1,
                updated_at=current,
            )
        )
        self._session.flush()
        return row if int(getattr(result, "rowcount", 0)) == 1 else None

    def mark_started(self, source_id: str, *, operation_id: str, now: datetime) -> bool:
        row = self.get(source_id)
        if row is None:
            return False
        result = self._session.execute(
            update(MailboxState)
            .where(
                MailboxState.source_id == source_id,
                MailboxState.operation_id == operation_id,
                MailboxState.last_request_at.is_(None),
                MailboxState.revision == row.revision,
            )
            .values(
                last_request_at=_utc(now),
                revision=MailboxState.revision + 1,
                updated_at=_utc(now),
            )
        )
        self._session.flush()
        return int(getattr(result, "rowcount", 0)) == 1

    def reconcile(
        self,
        source_id: str,
        *,
        expected_revision: int,
        observed_uidvalidity: int,
        acknowledgement: str,
        strategy: str,
        now: datetime,
    ) -> MailboxState:
        if strategy != "bounded-lookback" or acknowledgement != "accept-uidvalidity-change":
            raise ValueError("explicit bounded reconciliation acknowledgement is required")
        if observed_uidvalidity <= 0:
            raise ValueError("uidvalidity must be positive")
        row = self.get(source_id)
        if row is None:
            raise LookupError("mailbox state not found")
        if row.revision != expected_revision:
            raise ValueError("revision_conflict")
        row.uidvalidity = observed_uidvalidity
        row.highest_terminal_uid = 0
        row.last_error_code = None
        row.last_request_at = None
        row.operation_id = None
        row.revision += 1
        row.updated_at = _utc(now)
        self._session.flush()
        return row


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
