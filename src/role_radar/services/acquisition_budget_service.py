"""Transactional acquisition reservation and settlement service."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import AcquisitionReservation
from role_radar.discovery.acquisition_config import AcquisitionConfig
from role_radar.repositories.acquisition import AcquisitionRepository

Clock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class AcquisitionOperation:
    operation_key: str
    provider: str
    tier: str
    cycle_id: str
    query_key: str
    query_ordinal: int
    unit_price_micro_usd: int = 0


@dataclass(frozen=True, slots=True)
class ReservationHandle:
    reservation_id: str
    operation_key: str
    created: bool
    status: str


class AcquisitionBudgetService:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        config: AcquisitionConfig,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._config = config
        self._clock = clock or (lambda: datetime.now(UTC))

    def reserve(self, operation: AcquisitionOperation) -> ReservationHandle | None:
        now = self._clock().astimezone(UTC)
        unit_limit, micro_limit = self._limits(operation)
        with self._session_factory() as session:
            result = AcquisitionRepository(session).reserve(
                operation_key=operation.operation_key,
                provider=operation.provider,
                tier=operation.tier,
                utc_month=now.strftime("%Y-%m"),
                config_version=self._config.config_version,
                unit_limit=unit_limit,
                micro_usd_limit=micro_limit,
                units=1,
                micro_usd=operation.unit_price_micro_usd,
            )
            if result is None:
                session.rollback()
                return None
            session.commit()
            return ReservationHandle(
                result.reservation_id, result.operation_key, result.created, result.status
            )

    def release_before_transmission(self, handle: ReservationHandle) -> None:
        with self._session_factory() as session:
            AcquisitionRepository(session).settle(
                handle.reservation_id,
                status="released",
                transmission_status="not_sent",
                now=self._clock(),
            )
            session.commit()

    def finalize(
        self,
        operation: AcquisitionOperation,
        handle: ReservationHandle,
        *,
        status: str,
        candidate_count: int,
        known_count: int,
        unknown_count: int,
        rejected_count: int,
        duration_ms: int,
        error_code: str | None,
        transmission_status: str = "sent",
    ) -> None:
        now = self._clock().astimezone(UTC)
        with self._session_factory() as session:
            repository = AcquisitionRepository(session)
            repository.settle(
                handle.reservation_id,
                status="spent" if transmission_status != "not_sent" else "released",
                transmission_status=transmission_status,
                now=now,
            )
            repository.record_call(
                task_id=operation.cycle_id,
                operation_key=operation.operation_key,
                cycle_id=operation.cycle_id,
                query_key=operation.query_key,
                query_ordinal=operation.query_ordinal,
                provider=operation.provider,
                tier=operation.tier,
                status=status,
                candidate_count=candidate_count,
                known_count=known_count,
                unknown_count=unknown_count,
                rejected_count=rejected_count,
                duration_ms=duration_ms,
                error_code=error_code,
                reservation_id=handle.reservation_id,
                started_at=now,
                completed_at=now,
            )
            session.commit()

    def reconcile_open_reservations(self) -> int:
        """Crash recovery: an unprovable transmission is conservatively spent."""
        now = self._clock().astimezone(UTC)
        with self._session_factory() as session:
            repository = AcquisitionRepository(session)
            rows = list(
                session.scalars(
                    select(AcquisitionReservation).where(
                        AcquisitionReservation.status == "reserved"
                    )
                )
            )
            for row in rows:
                repository.settle(
                    row.id, status="spent", transmission_status="indeterminate", now=now
                )
            session.commit()
            return len(rows)

    def _limits(self, operation: AcquisitionOperation) -> tuple[int, int]:
        if operation.provider == "brave" and operation.tier == "paid":
            if not self._config.brave_paid.enabled or not self._config.paid_is_current(
                self._clock()
            ):
                return 0, 0
            if operation.unit_price_micro_usd <= 0:
                return 0, 0
            return 10_000_000, self._config.effective_brave_paid_cap
        if operation.provider == "brave" and operation.tier == "free":
            quota = self._config.brave_free
        elif operation.provider == "tavily" and operation.tier == "free":
            quota = self._config.tavily_free
        else:
            return 0, 0
        return quota.units_limit if quota.enabled else 0, 0
