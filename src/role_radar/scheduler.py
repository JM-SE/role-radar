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
