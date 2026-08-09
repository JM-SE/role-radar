"""Pure UTC due-slot policy for free sources."""

from datetime import UTC, datetime, timedelta

from role_radar.free_sources.contracts import FreeSourcePolicy

JOBICY_CADENCE_VERSION = "jobicy-hourly-v1"
JOBICY_POLICY_VERSION = "jobicy-latam-v1"
JOBICY_CADENCE = timedelta(hours=1)
JOBICY_POLICY = FreeSourcePolicy(
    source_type="jobicy",
    source_key="jobicy:latam",
    cadence_version=JOBICY_CADENCE_VERSION,
    policy_version=JOBICY_POLICY_VERSION,
    cadence_seconds=int(JOBICY_CADENCE.total_seconds()),
)


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("free-source timestamps must be timezone-aware")
    return value.astimezone(UTC)


def is_due(next_due_at: datetime, now: datetime) -> bool:
    return utc(now) >= utc(next_due_at)


def next_slot(slot: datetime) -> datetime:
    return utc(slot) + JOBICY_CADENCE


def reserve_one_slot(next_due_at: datetime, now: datetime) -> datetime | None:
    """Return only the exact expired slot; never catch up in a burst."""
    due = utc(next_due_at)
    return due if utc(now) >= due else None


def slot_operation_id(run_id: str, source_id: str, slot: datetime) -> str:
    return f"free:{run_id}:{source_id}:{utc(slot).isoformat()}"
