"""Pure Buenos Aires slot and deterministic source rotation helpers."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, date, datetime, time
from zoneinfo import ZoneInfo

from role_radar.continuous_acquisition.contracts import SLOT_VERSION

BUENOS_AIRES = ZoneInfo("America/Argentina/Buenos_Aires")


def daily_slot(day: date | datetime, *, namespace: str) -> str:
    local_day = day.astimezone(BUENOS_AIRES).date() if isinstance(day, datetime) else day
    return f"{namespace}:{SLOT_VERSION}:{local_day.isoformat()}"


def slot_datetime(day: date, hour: int) -> datetime:
    return datetime.combine(day, time(hour, 0), tzinfo=BUENOS_AIRES).astimezone(UTC)


def rotate_sources(source_ids: Sequence[str], *, day: date | datetime) -> tuple[str, ...]:
    local_day = day.astimezone(BUENOS_AIRES).date() if isinstance(day, datetime) else day
    return tuple(
        sorted(
            source_ids,
            key=lambda source_id: hashlib.sha256(f"{local_day.isoformat()}:{source_id}".encode()).hexdigest(),
        )
    )


def discovery_slot(day: date | datetime) -> str:
    return daily_slot(day, namespace="continuous-discovery")


def acquisition_slot(day: date | datetime) -> str:
    return daily_slot(day, namespace="continuous-acquisition")
