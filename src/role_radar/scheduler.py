"""Cálculo puro de slots lógicos para el timer diario."""

from datetime import UTC, datetime, timedelta


def latest_slot(
    now: datetime, *, schedule_id: str, hour_utc: int, minute_utc: int
) -> str:
    """Devuelve una clave estable para la ventana más reciente ya abierta."""
    current = now.astimezone(UTC)
    anchor = current.replace(hour=hour_utc, minute=minute_utc, second=0, microsecond=0)
    if anchor > current:
        anchor -= timedelta(days=1)
    return f"{schedule_id}:{anchor.strftime('%Y-%m-%dT%H:%M:%SZ')}"
