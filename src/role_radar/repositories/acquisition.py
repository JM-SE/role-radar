"""SQL-only acquisition budget, reservation, ledger and memo repository."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

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


ProviderV2 = Literal["brave", "tavily"]
TierV2 = Literal["free"]


class DiscoveryQuotaContextV2Protocol(Protocol):
    """Structural input accepted from the verified discovery configuration."""

    provider: str
    tier: str
    utc_month: str
    config_version: str
    unit_limit: int
    micro_usd_limit: int
    reservation_units_per_call: int
    reservation_micro_usd_per_call: int
    operation_max_calls: int


@dataclass(frozen=True, slots=True)
class DiscoveryQuotaContextV2:
    """The immutable, non-secret quota values bound to one operation."""

    provider: ProviderV2
    tier: TierV2
    utc_month: str
    config_version: str
    unit_limit: int
    micro_usd_limit: int
    reservation_units_per_call: int
    reservation_micro_usd_per_call: int
    operation_max_calls: int


@dataclass(frozen=True, slots=True)
class ProviderCallStartV2:
    """Immutable ledger identity published together with a reservation."""

    task_id: str
    operation_key: str
    cycle_id: str
    query_key: str
    query_ordinal: int
    provider: ProviderV2
    tier: TierV2
    started_at: datetime


@dataclass(frozen=True, slots=True)
class ProviderCallTerminalV2:
    """Terminal, sanitized outcome for one previously published ledger row."""

    operation_key: str
    status: Literal["succeeded", "empty", "failed", "malformed", "indeterminate"]
    transmission_status: Literal["not_sent", "sent", "indeterminate"]
    candidate_count: int
    known_count: int
    unknown_count: int
    rejected_count: int
    duration_ms: int
    error_code: str | None
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class ProviderCallRecordV2:
    """Typed compatibility input for the legacy one-row ledger writer."""

    task_id: str
    operation_key: str
    cycle_id: str
    query_key: str
    query_ordinal: int
    provider: ProviderV2
    tier: TierV2
    status: Literal["reserved", "succeeded", "empty", "failed", "malformed", "indeterminate"]
    candidate_count: int
    known_count: int
    unknown_count: int
    rejected_count: int
    duration_ms: int
    error_code: str | None
    reservation_id: str | None
    started_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class QuotaLedgerPublicationV2:
    """Scalar result safe to carry out of the SQL transaction/session."""

    reservation_id: str
    ledger_id: str
    operation_key: str
    reservation_status: str
    transmission_status: str
    ledger_status: str
    created: bool


QuotaContextV2Input = (
    DiscoveryQuotaContextV2 | DiscoveryQuotaContextV2Protocol | Mapping[str, object]
)


class AcquisitionQuotaLedgerV2(Protocol):
    """Focused report-only persistence seam.

    Implementations only flush.  The caller owns the surrounding transaction and
    must commit the start publication before transport and the finalization before
    publishing the terminal report (for example, ``with session.begin():``).
    """

    def publish_reservation_and_ledger_start_v2(
        self,
        *,
        operation_key: str,
        context: QuotaContextV2Input,
        start: ProviderCallStartV2,
    ) -> QuotaLedgerPublicationV2 | None: ...

    def finalize_reservation_and_ledger_v2(
        self,
        *,
        reservation_id: str,
        terminal: ProviderCallTerminalV2,
    ) -> QuotaLedgerPublicationV2: ...

    def revalidate_context_v2(
        self,
        *,
        operation_id: str,
        plan_sha256: str,
        context: QuotaContextV2Input,
    ) -> DiscoveryQuotaContextV2: ...

    def commit_v2(self) -> None: ...


class AcquisitionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._v2_operation_id: str | None = None

    def commit_v2(self) -> None:
        """Commit one report-only publication boundary.

        The provider adapter calls this only after a reservation/ledger start
        and after terminal finalization.  Legacy repository methods never use
        this method, so their transaction ownership remains unchanged.
        """

        operation_id = self._v2_operation_id
        if operation_id is None:
            raise ValueError("discovery_quota_evidence_invalid")
        prefix = f"cdv2:{operation_id}:"
        scoped_period_ids = set(
            self._session.scalars(
                select(AcquisitionReservation.period_id).where(
                    AcquisitionReservation.operation_key.startswith(prefix)
                )
            )
        )
        scoped_period_ids.update(
            item.period_id
            for item in self._session.new.union(self._session.dirty)
            if isinstance(item, AcquisitionReservation) and item.operation_key.startswith(prefix)
        )
        for collection in (self._session.new, self._session.dirty, self._session.deleted):
            for item in collection:
                if isinstance(item, (ProviderCallLedger, AcquisitionReservation)):
                    if not item.operation_key.startswith(prefix):
                        raise ValueError("discovery_quota_evidence_invalid")
                elif isinstance(item, AcquisitionBudgetPeriod):
                    if item.id not in scoped_period_ids:
                        raise ValueError("discovery_quota_evidence_invalid")
                else:
                    raise ValueError("discovery_quota_evidence_invalid")
        self._session.commit()

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

    @staticmethod
    def _v2_context_value(context: QuotaContextV2Input, name: str) -> object:
        if isinstance(context, Mapping):
            return context.get(name)
        return getattr(context, name, None)

    def _validate_v2_context(self, context: QuotaContextV2Input) -> DiscoveryQuotaContextV2:
        names = (
            "provider",
            "tier",
            "utc_month",
            "config_version",
            "unit_limit",
            "micro_usd_limit",
            "reservation_units_per_call",
            "reservation_micro_usd_per_call",
            "operation_max_calls",
        )
        values = {name: self._v2_context_value(context, name) for name in names}
        if values["provider"] not in {"brave", "tavily"} or values["tier"] != "free":
            raise ValueError("discovery_quota_context_invalid")
        if (
            not isinstance(values["utc_month"], str)
            or re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])", values["utc_month"]) is None
            or not isinstance(values["config_version"], str)
            or not values["config_version"]
        ):
            raise ValueError("discovery_quota_context_invalid")
        numeric_values = tuple(values[name] for name in names[4:])
        if any(type(value) is not int or value < 0 for value in numeric_values):
            raise ValueError("discovery_quota_context_invalid")
        reservation_units = cast(int, values["reservation_units_per_call"])
        operation_max_calls = cast(int, values["operation_max_calls"])
        if reservation_units <= 0 or operation_max_calls <= 0:
            raise ValueError("discovery_quota_context_invalid")
        return DiscoveryQuotaContextV2(
            provider=values["provider"],
            tier=values["tier"],
            utc_month=values["utc_month"],
            config_version=values["config_version"],
            unit_limit=cast(int, values["unit_limit"]),
            micro_usd_limit=cast(int, values["micro_usd_limit"]),
            reservation_units_per_call=reservation_units,
            reservation_micro_usd_per_call=cast(int, values["reservation_micro_usd_per_call"]),
            operation_max_calls=operation_max_calls,
        )

    @staticmethod
    def _validate_v2_operation_key(operation_key: object) -> tuple[str, str, int, ProviderV2]:
        if not isinstance(operation_key, str):
            raise ValueError("discovery_quota_operation_key_invalid")
        match = re.fullmatch(
            r"cdv2:([0-9a-f-]{36}):([0-9a-f]{64}):q([0-9]{2}):(brave|tavily)",
            operation_key,
        )
        if match is None:
            raise ValueError("discovery_quota_operation_key_invalid")
        operation_id, plan_sha256, ordinal, provider = match.groups()
        try:
            parsed = UUID(operation_id)
        except ValueError as exc:
            raise ValueError("discovery_quota_operation_key_invalid") from exc
        if (
            str(parsed) != operation_id
            or operation_id != operation_id.casefold()
            or not 1 <= int(ordinal) <= 4
        ):
            raise ValueError("discovery_quota_operation_key_invalid")
        return operation_id, plan_sha256, int(ordinal), cast(ProviderV2, provider)

    @staticmethod
    def _validate_v2_timestamp(value: object) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("discovery_quota_evidence_invalid")
        return value

    @classmethod
    def _validate_v2_start(
        cls, operation_key: str, start: ProviderCallStartV2
    ) -> tuple[str, str, int, ProviderV2]:
        operation_id, plan_sha256, query_ordinal, provider = cls._validate_v2_operation_key(
            operation_key
        )
        if (
            start.operation_key != operation_key
            or start.task_id != f"continuous-discovery-v2:{operation_id}"
            or start.cycle_id != operation_id
            or start.query_ordinal != query_ordinal
            or start.provider != provider
            or start.tier != "free"
            or not isinstance(start.query_key, str)
            or re.fullmatch(r"[0-9a-f]{64}", start.query_key) is None
        ):
            raise ValueError("discovery_quota_evidence_invalid")
        cls._validate_v2_timestamp(start.started_at)
        return operation_id, plan_sha256, query_ordinal, provider

    @staticmethod
    def _validate_v2_terminal(terminal: ProviderCallTerminalV2) -> None:
        if terminal.transmission_status not in {"not_sent", "sent", "indeterminate"}:
            raise ValueError("discovery_quota_evidence_invalid")
        if terminal.status not in {"succeeded", "empty", "failed", "malformed", "indeterminate"}:
            raise ValueError("discovery_quota_evidence_invalid")
        if terminal.status == "indeterminate" and terminal.transmission_status != "indeterminate":
            raise ValueError("discovery_quota_evidence_invalid")
        if terminal.transmission_status == "not_sent" and (
            terminal.status != "failed" or terminal.error_code != "pretransport_failed"
        ):
            raise ValueError("discovery_quota_evidence_invalid")
        if terminal.transmission_status == "sent" and terminal.status == "indeterminate":
            raise ValueError("discovery_quota_evidence_invalid")
        for value in (
            terminal.candidate_count,
            terminal.known_count,
            terminal.unknown_count,
            terminal.rejected_count,
            terminal.duration_ms,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("discovery_quota_evidence_invalid")
        if terminal.error_code is not None and terminal.error_code not in {
            "provider_failed",
            "provider_malformed",
            "provider_timeout",
            "pretransport_failed",
            "transmission_indeterminate",
        }:
            raise ValueError("discovery_quota_evidence_invalid")
        if terminal.error_code is not None and len(terminal.error_code) > 64:
            raise ValueError("discovery_quota_evidence_invalid")
        AcquisitionRepository._validate_v2_timestamp(terminal.completed_at)

    def _reconcile_v2_period(self, period: AcquisitionBudgetPeriod) -> None:
        reservations = list(
            self._session.scalars(
                select(AcquisitionReservation).where(AcquisitionReservation.period_id == period.id)
            )
        )
        for item in reservations:
            if item.units_reserved < 0 or item.micro_usd_reserved < 0:
                raise ValueError("discovery_quota_evidence_invalid")
            if item.status == "reserved" and (
                item.transmission_status != "not_sent" or item.settled_at is not None
            ):
                raise ValueError("discovery_quota_evidence_invalid")
            if item.status == "spent" and item.transmission_status not in {"sent", "indeterminate"}:
                raise ValueError("discovery_quota_evidence_invalid")
            if item.status == "released" and item.transmission_status != "not_sent":
                raise ValueError("discovery_quota_evidence_invalid")
            if item.status != "reserved" and item.settled_at is None:
                raise ValueError("discovery_quota_evidence_invalid")
        reserved_units = sum(
            item.units_reserved for item in reservations if item.status == "reserved"
        )
        reserved_cost = sum(
            item.micro_usd_reserved for item in reservations if item.status == "reserved"
        )
        used_units = sum(item.units_reserved for item in reservations if item.status == "spent")
        used_cost = sum(item.micro_usd_reserved for item in reservations if item.status == "spent")
        if (
            period.units_reserved != reserved_units
            or period.micro_usd_reserved != reserved_cost
            or period.units_used != used_units
            or period.micro_usd_used != used_cost
        ):
            raise ValueError("discovery_quota_evidence_invalid")

    def get_or_create_period_v2(self, context: QuotaContextV2Input) -> AcquisitionBudgetPeriod:
        """Get one exact free-tier period and reject context/counter drift."""

        values = self._validate_v2_context(context)
        period = self._session.scalar(
            select(AcquisitionBudgetPeriod)
            .where(
                AcquisitionBudgetPeriod.provider == values.provider,
                AcquisitionBudgetPeriod.tier == values.tier,
                AcquisitionBudgetPeriod.utc_month == values.utc_month,
            )
            .with_for_update()
        )
        if period is None:
            period = AcquisitionBudgetPeriod(
                id=str(uuid4()),
                provider=values.provider,
                tier=values.tier,
                utc_month=values.utc_month,
                config_version=values.config_version,
                unit_limit=values.unit_limit,
                micro_usd_limit=values.micro_usd_limit,
            )
            self._session.add(period)
            self._session.flush()
        elif any(
            getattr(period, name) != getattr(values, name)
            for name in (
                "provider",
                "tier",
                "utc_month",
                "config_version",
                "unit_limit",
                "micro_usd_limit",
            )
        ):
            raise ValueError("discovery_quota_context_stale")
        self._reconcile_v2_period(period)
        return period

    def reserve_v2(
        self, *, operation_key: str, context: QuotaContextV2Input
    ) -> ReservationResult | None:
        """Reserve one exact v2 free-tier unit with operation-key replay safety."""

        values = self._validate_v2_context(context)
        _, _, _, provider = self._validate_v2_operation_key(operation_key)
        if provider != values.provider:
            raise ValueError("discovery_quota_context_invalid")
        existing = self._session.scalar(
            select(AcquisitionReservation).where(
                AcquisitionReservation.operation_key == operation_key
            )
        )
        if existing is not None:
            period = self._session.get(AcquisitionBudgetPeriod, existing.period_id)
            if (
                period is None
                or period.provider != values.provider
                or period.tier != values.tier
                or period.utc_month != values.utc_month
                or existing.units_reserved != values.reservation_units_per_call
                or existing.micro_usd_reserved != values.reservation_micro_usd_per_call
            ):
                raise ValueError("discovery_quota_evidence_invalid")
            if existing.status != "reserved":
                raise ValueError("discovery_report_indeterminate")
            return ReservationResult(existing.id, existing.operation_key, False, existing.status)
        period = self.get_or_create_period_v2(context)
        units = values.reservation_units_per_call
        micro_usd = values.reservation_micro_usd_per_call
        if (
            period.units_used + period.units_reserved + units > period.unit_limit
            or period.micro_usd_used + period.micro_usd_reserved + micro_usd
            > period.micro_usd_limit
        ):
            return None
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
        return ReservationResult(row.id, operation_key, True, row.status)

    def _reconcile_v2_operation(
        self, operation_id: str, plan_sha256: str
    ) -> tuple[dict[str, AcquisitionReservation], dict[str, ProviderCallLedger]]:
        """Validate every matching v2 reservation/ledger pair without repairing it."""

        prefix = f"cdv2:{operation_id}:"
        reservations = list(
            self._session.scalars(
                select(AcquisitionReservation).where(
                    AcquisitionReservation.operation_key.startswith(prefix)
                )
            )
        )
        ledgers = list(
            self._session.scalars(
                select(ProviderCallLedger).where(
                    ProviderCallLedger.operation_key.startswith(prefix)
                )
            )
        )
        reservation_by_key = {item.operation_key: item for item in reservations}
        ledger_by_key = {item.operation_key: item for item in ledgers}
        if len(reservation_by_key) != len(reservations) or len(ledger_by_key) != len(ledgers):
            raise ValueError("discovery_quota_evidence_invalid")

        for key in set(reservation_by_key) | set(ledger_by_key):
            parsed_operation, parsed_plan, _, _ = self._validate_v2_operation_key(key)
            if parsed_operation != operation_id or parsed_plan != plan_sha256:
                raise ValueError("discovery_quota_evidence_invalid")
            reservation = reservation_by_key.get(key)
            ledger = ledger_by_key.get(key)
            if reservation is None or ledger is None or ledger.reservation_id != reservation.id:
                raise ValueError("discovery_quota_evidence_invalid")
            self._validate_v2_ledger_pair(reservation, ledger)
        return reservation_by_key, ledger_by_key

    def revalidate_context_v2(
        self,
        *,
        operation_id: str,
        plan_sha256: str,
        context: QuotaContextV2Input,
    ) -> DiscoveryQuotaContextV2:
        """Read and reconcile current v2 evidence without repairing it."""

        values = self._validate_v2_context(context)
        try:
            parsed_operation = str(UUID(operation_id))
        except ValueError as exc:
            raise ValueError("discovery_quota_evidence_invalid") from exc
        if parsed_operation != operation_id:
            raise ValueError("discovery_quota_evidence_invalid")
        period = self._session.scalar(
            select(AcquisitionBudgetPeriod).where(
                AcquisitionBudgetPeriod.provider == values.provider,
                AcquisitionBudgetPeriod.tier == values.tier,
                AcquisitionBudgetPeriod.utc_month == values.utc_month,
            )
        )
        if period is not None:
            if any(
                getattr(period, name) != getattr(values, name)
                for name in (
                    "provider",
                    "tier",
                    "utc_month",
                    "config_version",
                    "unit_limit",
                    "micro_usd_limit",
                )
            ):
                raise ValueError("discovery_quota_context_stale")
            self._reconcile_v2_period(period)
        self._reconcile_v2_operation(operation_id, plan_sha256)
        return values

    def preflight_replay_v2(self, *, operation_id: str, plan_sha256: str) -> None:
        """Reject matching incomplete quota evidence before a start marker."""

        reservations, ledgers = self._reconcile_v2_operation(operation_id, plan_sha256)
        if any(item.status == "reserved" for item in reservations.values()) or any(
            item.status == "reserved" for item in ledgers.values()
        ):
            raise ValueError("discovery_report_indeterminate")

    @classmethod
    def _validate_v2_ledger_pair(
        cls, reservation: AcquisitionReservation, ledger: ProviderCallLedger
    ) -> None:
        operation_id, _, query_ordinal, provider = cls._validate_v2_operation_key(
            ledger.operation_key
        )
        if (
            ledger.task_id != f"continuous-discovery-v2:{operation_id}"
            or ledger.cycle_id != operation_id
            or ledger.query_ordinal != query_ordinal
            or ledger.provider != provider
            or ledger.tier != "free"
            or re.fullmatch(r"[0-9a-f]{64}", ledger.query_key) is None
            or ledger.reservation_id != reservation.id
        ):
            raise ValueError("discovery_quota_evidence_invalid")
        if ledger.status == "reserved":
            if (
                reservation.status != "reserved"
                or reservation.transmission_status != "not_sent"
                or ledger.candidate_count != 0
                or ledger.known_count != 0
                or ledger.unknown_count != 0
                or ledger.rejected_count != 0
                or ledger.duration_ms != 0
                or ledger.error_code is not None
                or ledger.completed_at is not None
            ):
                raise ValueError("discovery_quota_evidence_invalid")
        elif ledger.status in {"succeeded", "empty", "failed", "malformed", "indeterminate"}:
            if ledger.completed_at is None or ledger.error_code not in {
                None,
                "provider_failed",
                "provider_malformed",
                "provider_timeout",
                "pretransport_failed",
                "transmission_indeterminate",
            }:
                raise ValueError("discovery_quota_evidence_invalid")
            if reservation.status == "released":
                if ledger.status != "failed" or ledger.error_code != "pretransport_failed":
                    raise ValueError("discovery_quota_evidence_invalid")
            elif reservation.status == "spent":
                if (
                    reservation.transmission_status == "indeterminate"
                    and ledger.status != "indeterminate"
                ):
                    raise ValueError("discovery_quota_evidence_invalid")
                if reservation.transmission_status == "sent" and ledger.status == "indeterminate":
                    raise ValueError("discovery_quota_evidence_invalid")
            else:
                raise ValueError("discovery_quota_evidence_invalid")
        else:
            raise ValueError("discovery_quota_evidence_invalid")

    def publish_reservation_and_ledger_start_v2(
        self,
        *,
        operation_key: str,
        context: QuotaContextV2Input,
        start: ProviderCallStartV2,
    ) -> QuotaLedgerPublicationV2 | None:
        """Flush reservation + ``reserved`` ledger start as one caller transaction unit.

        This method never commits.  Callers must wrap it in a transaction and
        commit the returned start publication before transport.  The adapter
        does not own rollback: validation and database errors must be handled by
        rolling back that caller-owned transaction boundary.
        """

        values = self._validate_v2_context(context)
        operation_id, plan_sha256, _, provider = self._validate_v2_start(operation_key, start)
        if self._v2_operation_id is not None and self._v2_operation_id != operation_id:
            raise ValueError("discovery_quota_evidence_invalid")
        self._v2_operation_id = operation_id
        if provider != values.provider:
            raise ValueError("discovery_quota_context_invalid")
        # This is deliberately a flush-only boundary.  A SAVEPOINT here can
        # become the SQLite transaction when the caller has not begun one;
        # callers own rollback/commit for the actual atomic publication.
        with self._session.no_autoflush:
            reservation_by_key, ledger_by_key = self._reconcile_v2_operation(
                operation_id, plan_sha256
            )
            if operation_key in reservation_by_key or operation_key in ledger_by_key:
                raise ValueError("discovery_report_indeterminate")
            period = self.get_or_create_period_v2(values)
            if (
                sum(1 for item in ledger_by_key.values() if item.provider == provider)
                >= values.operation_max_calls
            ):
                return None
            units = values.reservation_units_per_call
            micro_usd = values.reservation_micro_usd_per_call
            if (
                period.units_used + period.units_reserved + units > period.unit_limit
                or period.micro_usd_used + period.micro_usd_reserved + micro_usd
                > period.micro_usd_limit
            ):
                return None
            reservation = AcquisitionReservation(
                id=str(uuid4()),
                operation_key=operation_key,
                period_id=period.id,
                units_reserved=units,
                micro_usd_reserved=micro_usd,
                status="reserved",
                transmission_status="not_sent",
            )
            period.units_reserved += units
            period.micro_usd_reserved += micro_usd
            ledger = ProviderCallLedger(
                id=str(uuid4()),
                task_id=start.task_id,
                operation_key=operation_key,
                cycle_id=start.cycle_id,
                query_key=start.query_key,
                query_ordinal=start.query_ordinal,
                provider=start.provider,
                tier=start.tier,
                status="reserved",
                candidate_count=0,
                known_count=0,
                unknown_count=0,
                rejected_count=0,
                duration_ms=0,
                error_code=None,
                reservation_id=reservation.id,
                started_at=start.started_at,
                completed_at=None,
            )
            self._session.add_all((reservation, ledger))
            self._session.flush()
            return QuotaLedgerPublicationV2(
                reservation_id=reservation.id,
                ledger_id=ledger.id,
                operation_key=operation_key,
                reservation_status=reservation.status,
                transmission_status=reservation.transmission_status,
                ledger_status=ledger.status,
                created=True,
            )

    def reserve_and_start_v2(
        self,
        *,
        operation_key: str,
        context: QuotaContextV2Input,
        start: ProviderCallStartV2,
    ) -> QuotaLedgerPublicationV2 | None:
        """Compatibility spelling for the explicit atomic start seam."""

        return self.publish_reservation_and_ledger_start_v2(
            operation_key=operation_key, context=context, start=start
        )

    def finalize_reservation_and_ledger_v2(
        self,
        *,
        reservation_id: str,
        terminal: ProviderCallTerminalV2,
    ) -> QuotaLedgerPublicationV2:
        """Flush one legal reservation/ledger terminal transition atomically.

        No commit is performed.  The caller must commit this boundary before
        publishing the terminal report.  Replaying the exact terminal evidence
        is a no-op; contradictory, reopened, or incomplete evidence is rejected.
        """

        self._validate_v2_terminal(terminal)
        operation_id, plan_sha256, _, _ = self._validate_v2_operation_key(terminal.operation_key)
        if self._v2_operation_id is not None and self._v2_operation_id != operation_id:
            raise ValueError("discovery_quota_evidence_invalid")
        self._v2_operation_id = operation_id
        with self._session.no_autoflush:
            reservation = self._session.scalar(
                select(AcquisitionReservation)
                .where(AcquisitionReservation.id == reservation_id)
                .with_for_update()
            )
            ledger = self._session.scalar(
                select(ProviderCallLedger)
                .where(ProviderCallLedger.operation_key == terminal.operation_key)
                .with_for_update()
            )
            if reservation is None or ledger is None:
                raise ValueError("discovery_quota_evidence_invalid")
            if ledger.reservation_id != reservation.id:
                raise ValueError("discovery_quota_evidence_invalid")
            self._validate_v2_ledger_pair(reservation, ledger)
            reservation_by_key, ledger_by_key = self._reconcile_v2_operation(
                operation_id, plan_sha256
            )
            if (
                reservation_by_key.get(terminal.operation_key) is not reservation
                or ledger_by_key.get(terminal.operation_key) is not ledger
            ):
                raise ValueError("discovery_quota_evidence_invalid")
            if ledger.status != "reserved" or reservation.status != "reserved":
                if self._v2_terminal_matches(terminal, reservation, ledger):
                    return QuotaLedgerPublicationV2(
                        reservation_id=reservation.id,
                        ledger_id=ledger.id,
                        operation_key=terminal.operation_key,
                        reservation_status=reservation.status,
                        transmission_status=reservation.transmission_status,
                        ledger_status=ledger.status,
                        created=False,
                    )
                raise ValueError("discovery_quota_evidence_invalid")
            period = self._session.scalar(
                select(AcquisitionBudgetPeriod)
                .where(AcquisitionBudgetPeriod.id == reservation.period_id)
                .with_for_update()
            )
            if period is None:
                raise ValueError("discovery_quota_evidence_invalid")
            self._reconcile_v2_period(period)
            if terminal.transmission_status == "not_sent":
                reservation.status = "released"
            else:
                reservation.status = "spent"
                period.units_used += reservation.units_reserved
                period.micro_usd_used += reservation.micro_usd_reserved
            period.units_reserved -= reservation.units_reserved
            period.micro_usd_reserved -= reservation.micro_usd_reserved
            reservation.transmission_status = terminal.transmission_status
            reservation.settled_at = terminal.completed_at
            ledger.status = terminal.status
            ledger.candidate_count = terminal.candidate_count
            ledger.known_count = terminal.known_count
            ledger.unknown_count = terminal.unknown_count
            ledger.rejected_count = terminal.rejected_count
            ledger.duration_ms = terminal.duration_ms
            ledger.error_code = terminal.error_code
            ledger.completed_at = terminal.completed_at
            self._session.flush()
            return QuotaLedgerPublicationV2(
                reservation_id=reservation.id,
                ledger_id=ledger.id,
                operation_key=terminal.operation_key,
                reservation_status=reservation.status,
                transmission_status=reservation.transmission_status,
                ledger_status=ledger.status,
                created=False,
            )

    def finalize_v2(
        self,
        *,
        reservation_id: str,
        terminal: ProviderCallTerminalV2,
    ) -> QuotaLedgerPublicationV2:
        """Compatibility spelling for the explicit atomic finalization seam."""

        return self.finalize_reservation_and_ledger_v2(
            reservation_id=reservation_id, terminal=terminal
        )

    @staticmethod
    def _v2_terminal_matches(
        terminal: ProviderCallTerminalV2,
        reservation: AcquisitionReservation,
        ledger: ProviderCallLedger,
    ) -> bool:
        return (
            reservation.status
            == ("released" if terminal.transmission_status == "not_sent" else "spent")
            and reservation.transmission_status == terminal.transmission_status
            and ledger.status == terminal.status
            and ledger.candidate_count == terminal.candidate_count
            and ledger.known_count == terminal.known_count
            and ledger.unknown_count == terminal.unknown_count
            and ledger.rejected_count == terminal.rejected_count
            and ledger.duration_ms == terminal.duration_ms
            and ledger.error_code == terminal.error_code
            and AcquisitionRepository._v2_same_timestamp(ledger.completed_at, terminal.completed_at)
            and AcquisitionRepository._v2_same_timestamp(
                reservation.settled_at, terminal.completed_at
            )
        )

    @staticmethod
    def _v2_same_timestamp(left: datetime | None, right: datetime | None) -> bool:
        if left is None or right is None:
            return left is right
        if left.tzinfo is None:
            left = left.replace(tzinfo=UTC)
        if right.tzinfo is None:
            right = right.replace(tzinfo=UTC)
        return left.astimezone(UTC) == right.astimezone(UTC)

    def settle_v2(
        self,
        reservation_id: str,
        *,
        transmission_status: str,
        sent: bool,
        now: datetime,
    ) -> AcquisitionReservation:
        """Settle only a v2 reservation; no reopen/reset/recovery is performed."""

        if transmission_status not in {"not_sent", "sent", "indeterminate"}:
            raise ValueError("discovery_quota_evidence_invalid")
        if type(sent) is not bool or (sent and transmission_status == "not_sent"):
            raise ValueError("discovery_quota_evidence_invalid")
        status = "spent" if sent or transmission_status != "not_sent" else "released"
        return self.settle(
            reservation_id,
            status=status,
            transmission_status=transmission_status,
            now=now,
        )

    def record_call_v2(
        self, record: ProviderCallRecordV2 | None = None, **values: object
    ) -> ProviderCallLedger:
        """Validate/write one v2 row without changing any existing row.

        ``**values`` remains accepted for callers of the provisional v2 API;
        new code should pass :class:`ProviderCallRecordV2`.
        """

        if record is None:
            try:
                record = ProviderCallRecordV2(
                    task_id=cast(str, values["task_id"]),
                    operation_key=cast(str, values["operation_key"]),
                    cycle_id=cast(str, values["cycle_id"]),
                    query_key=cast(str, values["query_key"]),
                    query_ordinal=cast(int, values["query_ordinal"]),
                    provider=cast(ProviderV2, values["provider"]),
                    tier=cast(TierV2, values["tier"]),
                    status=cast(
                        Literal[
                            "reserved",
                            "succeeded",
                            "empty",
                            "failed",
                            "malformed",
                            "indeterminate",
                        ],
                        values["status"],
                    ),
                    candidate_count=cast(int, values["candidate_count"]),
                    known_count=cast(int, values["known_count"]),
                    unknown_count=cast(int, values["unknown_count"]),
                    rejected_count=cast(int, values["rejected_count"]),
                    duration_ms=cast(int, values["duration_ms"]),
                    error_code=cast(str | None, values["error_code"]),
                    reservation_id=cast(str | None, values["reservation_id"]),
                    started_at=cast(datetime, values["started_at"]),
                    completed_at=cast(datetime | None, values["completed_at"]),
                )
            except (KeyError, TypeError) as exc:
                raise ValueError("discovery_quota_evidence_invalid") from exc
        _, _, query_ordinal, provider = self._validate_v2_start(
            record.operation_key,
            ProviderCallStartV2(
                task_id=record.task_id,
                operation_key=record.operation_key,
                cycle_id=record.cycle_id,
                query_key=record.query_key,
                query_ordinal=record.query_ordinal,
                provider=record.provider,
                tier=record.tier,
                started_at=record.started_at,
            ),
        )
        if provider != record.provider or record.status not in {
            "reserved",
            "succeeded",
            "empty",
            "failed",
            "malformed",
            "indeterminate",
        }:
            raise ValueError("discovery_quota_evidence_invalid")
        if record.status == "reserved" and (
            record.completed_at is not None
            or record.error_code is not None
            or any(
                value != 0
                for value in (
                    record.candidate_count,
                    record.known_count,
                    record.unknown_count,
                    record.rejected_count,
                    record.duration_ms,
                )
            )
        ):
            raise ValueError("discovery_quota_evidence_invalid")
        for value in (
            record.candidate_count,
            record.known_count,
            record.unknown_count,
            record.rejected_count,
            record.duration_ms,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("discovery_quota_evidence_invalid")
        completed_at = record.completed_at
        terminal: ProviderCallTerminalV2 | None = None
        if record.status != "reserved":
            if completed_at is None:
                raise ValueError("discovery_quota_evidence_invalid")
            transmission_status: Literal["not_sent", "sent", "indeterminate"] = (
                "not_sent"
                if record.error_code == "pretransport_failed"
                else "indeterminate"
                if record.status == "indeterminate"
                else "sent"
            )
            terminal = ProviderCallTerminalV2(
                operation_key=record.operation_key,
                status=record.status,
                transmission_status=transmission_status,
                candidate_count=record.candidate_count,
                known_count=record.known_count,
                unknown_count=record.unknown_count,
                rejected_count=record.rejected_count,
                duration_ms=record.duration_ms,
                error_code=record.error_code,
                completed_at=completed_at,
            )
            self._validate_v2_terminal(terminal)
        existing = self._session.scalar(
            select(ProviderCallLedger).where(
                ProviderCallLedger.operation_key == record.operation_key
            )
        )
        if existing is not None:
            immutable = (
                "task_id",
                "cycle_id",
                "query_key",
                "query_ordinal",
                "provider",
                "tier",
                "reservation_id",
                "started_at",
            )
            if any(
                (
                    not self._v2_same_timestamp(getattr(existing, name), getattr(record, name))
                    if name == "started_at"
                    else getattr(existing, name) != getattr(record, name)
                )
                for name in immutable
            ):
                raise ValueError("discovery_quota_evidence_invalid")
            if existing.status == "reserved" and terminal is not None:
                if existing.reservation_id is None:
                    raise ValueError("discovery_quota_evidence_invalid")
                self.finalize_reservation_and_ledger_v2(
                    reservation_id=existing.reservation_id,
                    terminal=terminal,
                )
                return existing
            if any(
                getattr(existing, name) != getattr(record, name)
                for name in (
                    "status",
                    "candidate_count",
                    "known_count",
                    "unknown_count",
                    "rejected_count",
                    "duration_ms",
                    "error_code",
                    "completed_at",
                )
            ):
                raise ValueError("discovery_quota_evidence_invalid")
            return existing
        if record.status != "reserved" or record.reservation_id is None:
            raise ValueError("discovery_quota_evidence_invalid")
        reservation = self._session.get(AcquisitionReservation, record.reservation_id)
        if reservation is None:
            raise ValueError("discovery_quota_evidence_invalid")
        row = self.record_call(
            task_id=record.task_id,
            operation_key=record.operation_key,
            cycle_id=record.cycle_id,
            query_key=record.query_key,
            query_ordinal=query_ordinal,
            provider=record.provider,
            tier=record.tier,
            status=record.status,
            candidate_count=record.candidate_count,
            known_count=record.known_count,
            unknown_count=record.unknown_count,
            rejected_count=record.rejected_count,
            duration_ms=record.duration_ms,
            error_code=record.error_code,
            reservation_id=record.reservation_id,
            started_at=record.started_at,
            completed_at=cast(datetime, completed_at),
        )
        self._validate_v2_ledger_pair(reservation, row)
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
