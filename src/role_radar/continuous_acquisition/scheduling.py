"""Pure Buenos Aires slot and deterministic source rotation helpers."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from datetime import UTC, date, datetime, time
from zoneinfo import ZoneInfo

from role_radar.continuous_acquisition.contracts import SLOT_VERSION

BUENOS_AIRES = ZoneInfo("America/Argentina/Buenos_Aires")
_CANARY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def daily_slot(day: date | datetime, *, namespace: str) -> str:
    local_day = day.astimezone(BUENOS_AIRES).date() if isinstance(day, datetime) else day
    return f"{namespace}:{SLOT_VERSION}:{local_day.isoformat()}"


def daily_canary_slot(
    day: date | datetime, *, namespace: str, canary_id: str
) -> str:
    if _CANARY_ID.fullmatch(canary_id) is None:
        raise ValueError("canary_id_invalid")
    local_day = day.astimezone(BUENOS_AIRES).date() if isinstance(day, datetime) else day
    return f"{namespace}-canary:{SLOT_VERSION}:{local_day.isoformat()}:{canary_id}"


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


def discovery_slot(day: date | datetime, *, canary_id: str | None = None) -> str:
    if canary_id is None:
        return daily_slot(day, namespace="continuous-discovery")
    return daily_canary_slot(
        day, namespace="continuous-discovery", canary_id=canary_id
    )


def acquisition_slot(day: date | datetime, *, canary_id: str | None = None) -> str:
    if canary_id is None:
        return daily_slot(day, namespace="continuous-acquisition")
    return daily_canary_slot(
        day, namespace="continuous-acquisition", canary_id=canary_id
    )
