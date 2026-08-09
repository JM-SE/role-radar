"""SQL-only acquisition budget, reservation, ledger and memo repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import (
    AcquisitionBudgetPeriod,
    AcquisitionReservation,
    DiscoveryQueryMemo,
    ProviderCallLedger,
)


@dataclass(frozen=True, slots=True)
class ReservationResult:
    reservation_id: str
    operation_key: str
    created: bool
    status: str


class AcquisitionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_or_create_period(
        self,
        *,
        provider: str,
        tier: str,
        utc_month: str,
        config_version: str,
        unit_limit: int,
        micro_usd_limit: int,
    ) -> AcquisitionBudgetPeriod:
        row = self._session.scalar(
            select(AcquisitionBudgetPeriod)
            .where(
                AcquisitionBudgetPeriod.provider == provider,
                AcquisitionBudgetPeriod.tier == tier,
                AcquisitionBudgetPeriod.utc_month == utc_month,
            )
            .with_for_update()
        )
        if row is not None:
            return row
        row = AcquisitionBudgetPeriod(
            id=str(uuid4()),
            provider=provider,
            tier=tier,
            utc_month=utc_month,
            config_version=config_version,
            unit_limit=unit_limit,
            micro_usd_limit=micro_usd_limit,
        )
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
        except IntegrityError:
            existing = self._session.scalar(
                select(AcquisitionBudgetPeriod).where(
                    AcquisitionBudgetPeriod.provider == provider,
                    AcquisitionBudgetPeriod.tier == tier,
                    AcquisitionBudgetPeriod.utc_month == utc_month,
                )
            )
            if existing is None:
                raise
            return existing
        return row

    def reserve(
        self,
        *,
        operation_key: str,
        provider: str,
        tier: str,
        utc_month: str,
        config_version: str,
        unit_limit: int,
        micro_usd_limit: int,
        units: int = 1,
        micro_usd: int = 0,
    ) -> ReservationResult | None:
        existing = self._session.scalar(
            select(AcquisitionReservation).where(
                AcquisitionReservation.operation_key == operation_key
            )
        )
        if existing is not None:
            return ReservationResult(existing.id, existing.operation_key, False, existing.status)
        if min(units, micro_usd, unit_limit, micro_usd_limit) < 0:
            raise ValueError("budget values must be non-negative")
        period = self.get_or_create_period(
            provider=provider,
            tier=tier,
            utc_month=utc_month,
            config_version=config_version,
            unit_limit=unit_limit,
            micro_usd_limit=micro_usd_limit,
        )
        if (
            period.units_used + period.units_reserved + units > period.unit_limit
            or period.micro_usd_used + period.micro_usd_reserved + micro_usd
            > period.micro_usd_limit
        ):
            return None
        try:
            with self._session.begin_nested():
                period.units_reserved += units
                period.micro_usd_reserved += micro_usd
                row = AcquisitionReservation(
                    id=str(uuid4()),
                    operation_key=operation_key,
                    period_id=period.id,
                    units_reserved=units,
                    micro_usd_reserved=micro_usd,
                    status="reserved",
                    transmission_status="not_sent",
                )
                self._session.add(row)
                self._session.flush()
        except IntegrityError:
            existing = self._session.scalar(
                select(AcquisitionReservation).where(
                    AcquisitionReservation.operation_key == operation_key
                )
            )
            if existing is None:
                raise
            return ReservationResult(existing.id, existing.operation_key, False, existing.status)
        return ReservationResult(row.id, operation_key, True, row.status)

    def get_reservation(self, reservation_id: str) -> AcquisitionReservation | None:
        return self._session.get(AcquisitionReservation, reservation_id)

    def settle(
        self,
        reservation_id: str,
        *,
        status: str,
        transmission_status: str,
        now: datetime,
    ) -> AcquisitionReservation:
        row = self._session.get(AcquisitionReservation, reservation_id)
        if row is None:
            raise LookupError("acquisition reservation not found")
        if row.status != "reserved":
            return row
        period = self._session.get(AcquisitionBudgetPeriod, row.period_id)
        if period is None:
            raise LookupError("acquisition budget period not found")
        if status == "released" and transmission_status == "not_sent":
            period.units_reserved -= row.units_reserved
            period.micro_usd_reserved -= row.micro_usd_reserved
        else:
            period.units_reserved -= row.units_reserved
            period.micro_usd_reserved -= row.micro_usd_reserved
            period.units_used += row.units_reserved
            period.micro_usd_used += row.micro_usd_reserved
            status = "spent"
        row.status = status
        row.transmission_status = transmission_status
        row.settled_at = now
        self._session.flush()
        return row

    def record_call(
        self,
        *,
        task_id: str,
        operation_key: str,
        cycle_id: str,
        query_key: str,
        query_ordinal: int,
        provider: str,
        tier: str,
        status: str,
        candidate_count: int,
        known_count: int,
        unknown_count: int,
        rejected_count: int,
        duration_ms: int,
        error_code: str | None,
        reservation_id: str | None,
        started_at: datetime,
        completed_at: datetime,
    ) -> ProviderCallLedger:
        row = self._session.scalar(
            select(ProviderCallLedger).where(ProviderCallLedger.operation_key == operation_key)
        )
        if row is not None:
            return row
        row = ProviderCallLedger(
            id=str(uuid4()),
            task_id=task_id,
            operation_key=operation_key,
            cycle_id=cycle_id,
            query_key=query_key,
            query_ordinal=query_ordinal,
            provider=provider,
            tier=tier,
            status=status,
            candidate_count=max(0, candidate_count),
            known_count=max(0, known_count),
            unknown_count=max(0, unknown_count),
            rejected_count=max(0, rejected_count),
            duration_ms=max(0, duration_ms),
            error_code=error_code[:64] if error_code else None,
            reservation_id=reservation_id,
            started_at=started_at,
            completed_at=completed_at,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def find_memo(
        self,
        *,
        provider: str,
        tier: str,
        query_key: str,
        planner_version: str,
        query_version: str,
        config_version: str,
        now: datetime,
    ) -> DiscoveryQueryMemo | None:
        row = self._session.scalar(
            select(DiscoveryQueryMemo).where(
                DiscoveryQueryMemo.provider == provider,
                DiscoveryQueryMemo.tier == tier,
                DiscoveryQueryMemo.query_key == query_key,
                DiscoveryQueryMemo.planner_version == planner_version,
                DiscoveryQueryMemo.query_version == query_version,
                DiscoveryQueryMemo.config_version == config_version,
            )
        )
        if row is None or row.status not in {"succeeded", "empty"}:
            return None
        if not row.executed_at <= now < row.expires_at:
            return None
        return row

    def upsert_memo(
        self,
        *,
        provider: str,
        tier: str,
        query_key: str,
        planner_version: str,
        query_version: str,
        config_version: str,
        executed_at: datetime,
        expires_at: datetime,
        status: str,
        candidate_count: int,
        known_count: int,
    ) -> DiscoveryQueryMemo:
        row = self._session.scalar(
            select(DiscoveryQueryMemo).where(
                DiscoveryQueryMemo.provider == provider,
                DiscoveryQueryMemo.tier == tier,
                DiscoveryQueryMemo.query_key == query_key,
                DiscoveryQueryMemo.planner_version == planner_version,
                DiscoveryQueryMemo.query_version == query_version,
                DiscoveryQueryMemo.config_version == config_version,
            )
        )
        if row is None:
            row = DiscoveryQueryMemo(
                id=str(uuid4()),
                provider=provider,
                tier=tier,
                query_key=query_key,
                planner_version=planner_version,
                query_version=query_version,
                config_version=config_version,
                executed_at=executed_at,
                expires_at=expires_at,
                status=status,
                candidate_count=max(0, candidate_count),
                known_count=max(0, known_count),
            )
            self._session.add(row)
        else:
            row.executed_at = executed_at
            row.expires_at = expires_at
            row.status = status
            row.candidate_count = max(0, candidate_count)
            row.known_count = max(0, known_count)
        self._session.flush()
        return row

    def list_periods(self, *, utc_month: str | None = None) -> list[AcquisitionBudgetPeriod]:
        statement = select(AcquisitionBudgetPeriod).order_by(
            AcquisitionBudgetPeriod.utc_month.desc(),
            AcquisitionBudgetPeriod.provider,
            AcquisitionBudgetPeriod.tier,
        )
        if utc_month is not None:
            statement = statement.where(AcquisitionBudgetPeriod.utc_month == utc_month)
        return list(self._session.scalars(statement))

    def latest_call(self) -> ProviderCallLedger | None:
        return self._session.scalar(
            select(ProviderCallLedger).order_by(ProviderCallLedger.completed_at.desc()).limit(1)
        )

    def purge_closed_periods(self, *, before_month: str) -> int:
        """Delete old ledger rows in FK-safe order; current memos are untouched."""
        periods = list(
            self._session.scalars(
                select(AcquisitionBudgetPeriod).where(
                    AcquisitionBudgetPeriod.utc_month < before_month
                )
            )
        )
        removed = 0
        for period in periods:
            reservations = list(
                self._session.scalars(
                    select(AcquisitionReservation).where(
                        AcquisitionReservation.period_id == period.id
                    )
                )
            )
            if any(item.status == "reserved" for item in reservations):
                continue
            ledgers = [
                ledger
                for item in reservations
                if (
                    ledger := self._session.scalar(
                        select(ProviderCallLedger).where(
                            ProviderCallLedger.reservation_id == item.id
                        )
                    )
                )
            ]
            for ledger in ledgers:
                self._session.delete(ledger)
            for item in reservations:
                self._session.delete(item)
            self._session.delete(period)
            removed += 1
        self._session.flush()
        return removed
