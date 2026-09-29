"""Cálculo puro de slots lógicos para el timer diario."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo


def latest_slot(
    now: datetime,
    *,
    schedule_id: str = "daily",
    hour_local: int = 8,
    minute_local: int = 0,
    timezone_name: str = "America/Argentina/Buenos_Aires",
    hour_utc: int | None = None,
    minute_utc: int | None = None,
) -> str:
    """Return the versioned local-day slot, using an explicit timezone."""
    legacy_utc = hour_utc is not None or minute_utc is not None
    if hour_utc is not None:
        hour_local = hour_utc
    if minute_utc is not None:
        minute_local = minute_utc
    zone = UTC if legacy_utc else ZoneInfo(timezone_name)
    current = now.astimezone(zone)
    anchor = current.replace(hour=hour_local, minute=minute_local, second=0, microsecond=0)
    if anchor > current:
        anchor -= timedelta(days=1)
    if legacy_utc:
        return f"{schedule_id}:{anchor.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}"
    return f"{schedule_id}:{anchor.strftime('%Y-%m-%d')}"


def latest_interval_slot(
    now: datetime,
    *,
    schedule_id: str = "source-campaign",
    interval_hours: int = 6,
    timezone_name: str = "America/Argentina/Buenos_Aires",
) -> str:
    """Return a stable wall-clock slot aligned with local calendar timers.

    The interval is a local civil-time cadence, not a promise of equal elapsed
    seconds across daylight-saving transitions. Slot keys include the UTC
    offset so their identity remains unambiguous when local clocks change.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("interval slots require a timezone-aware datetime")
    if not schedule_id.strip():
        raise ValueError("schedule_id must not be empty")
    if type(interval_hours) is not int or interval_hours <= 0 or 24 % interval_hours:
        raise ValueError("interval_hours must be a positive divisor of 24")

    zone = ZoneInfo(timezone_name)
    current = now.astimezone(zone)
    start_hour = (current.hour // interval_hours) * interval_hours
    anchor = current.replace(hour=start_hour, minute=0, second=0, microsecond=0)
    return f"{schedule_id}:{anchor.isoformat(timespec='seconds')}"
