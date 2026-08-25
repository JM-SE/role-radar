"""Short transactional CAS operations for durable free-source poll state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import SourcePollState
from role_radar.free_sources.due_policy import (
    JOBICY_CADENCE_VERSION,
    JOBICY_POLICY,
    next_slot,
    reserve_one_slot,
    slot_operation_id,
    utc,
)


@dataclass(frozen=True, slots=True)
class PollReservation:
    status: str
    reservation_id: str | None = None
    operation_id: str | None = None
    due_slot: datetime | None = None


class SourcePollStateRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, source_id: str) -> SourcePollState | None:
        return self._session.scalar(
            select(SourcePollState).where(SourcePollState.source_id == source_id)
        )

    def ensure_jobicy(self, source_id: str, *, now: datetime) -> SourcePollState:
        row = self.get(source_id)
        if row is not None:
            return row
        current = utc(now)
        row = SourcePollState(
            id=str(uuid4()),
            source_id=source_id,
            cadence_version=JOBICY_CADENCE_VERSION,
            policy_version=JOBICY_POLICY.policy_version,
            next_due_at=current,
            revision=1,
            created_at=current,
            updated_at=current,
        )
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
            return row
        except IntegrityError:
            existing = self.get(source_id)
            if existing is None:
                raise
            return existing

    def reserve_jobicy(self, source_id: str, *, run_id: str, now: datetime) -> PollReservation:
        current = utc(now)
        row = self.get(source_id)
        if row is None:
            row = self.ensure_jobicy(source_id, now=current)
        # A restarted worker may complete the pre-I/O part of the same run
        # without creating a second operation or slot.
        previous_slot = _db_utc(row.last_reserved_slot)
        if (
            row.operation_id is not None
            and row.operation_id.startswith(f"free:{run_id}:")
            and row.last_request_at is None
            and previous_slot is not None
        ):
            return PollReservation(
                "reused",
                row.reservation_id,
                row.operation_id,
                previous_slot,
            )
        next_due = _db_utc(row.next_due_at) or current
        if previous_slot is not None and previous_slot <= current < next_due:
            return PollReservation("already_reserved", due_slot=previous_slot)
        due_slot = reserve_one_slot(next_due, current)
        if due_slot is None:
            return PollReservation("not_due")

        reservation_id = str(uuid4())
        operation_id = slot_operation_id(run_id, source_id, due_slot)
        result = self._session.execute(
            update(SourcePollState)
            .where(
                SourcePollState.source_id == source_id,
                SourcePollState.revision == row.revision,
                SourcePollState.next_due_at == row.next_due_at,
            )
            .values(
                last_reserved_slot=due_slot,
                next_due_at=next_slot(due_slot),
                reservation_id=reservation_id,
                operation_id=operation_id,
                last_error_code=None,
                revision=SourcePollState.revision + 1,
                updated_at=current,
            )
        )
        self._session.flush()
        if int(getattr(result, "rowcount", 0)) != 1:
            return PollReservation("already_reserved", due_slot=due_slot)
        return PollReservation("reserved", reservation_id, operation_id, due_slot)

    def mark_request_started(self, source_id: str, *, operation_id: str, now: datetime) -> bool:
        current = utc(now)
        row = self.get(source_id)
        if row is None:
            return False
        result = self._session.execute(
            update(SourcePollState)
            .where(
                SourcePollState.source_id == source_id,
                SourcePollState.operation_id == operation_id,
                SourcePollState.last_request_at.is_(None),
                SourcePollState.revision == row.revision,
            )
            .values(
                last_request_at=current,
                revision=SourcePollState.revision + 1,
                updated_at=current,
            )
        )
        self._session.flush()
        return bool(int(getattr(result, "rowcount", 0)) == 1)

    def finalize(
        self,
        source_id: str,
        *,
        operation_id: str,
        now: datetime,
        success: bool,
        error_code: str | None = None,
    ) -> SourcePollState:
        row = self.get(source_id)
        if row is None or row.operation_id != operation_id:
            raise LookupError("free-source reservation not found")
        current = utc(now)
        if success:
            row.last_success_at = current
            row.last_error_code = None
        else:
            row.last_error_code = error_code
        row.updated_at = current
        row.revision += 1
        self._session.flush()
        return row


def _db_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
