from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from role_radar.scheduler import latest_interval_slot

BA = ZoneInfo("America/Argentina/Buenos_Aires")


def test_interval_slot_is_stable_inside_bucket_and_distinct_at_boundary() -> None:
    before_boundary = datetime(2026, 9, 28, 11, 59, tzinfo=BA)
    at_boundary = datetime(2026, 9, 28, 12, 0, tzinfo=BA)

    assert latest_interval_slot(before_boundary) == latest_interval_slot(
        before_boundary.replace(minute=5)
    )
    assert latest_interval_slot(before_boundary) == (
        "source-campaign:2026-09-28T06:00:00-03:00"
    )
    assert latest_interval_slot(at_boundary) == "source-campaign:2026-09-28T12:00:00-03:00"


def test_interval_slot_normalizes_instants_to_the_requested_timezone() -> None:
    instant = datetime(2026, 9, 28, 9, 0, tzinfo=UTC)

    assert latest_interval_slot(instant) == "source-campaign:2026-09-28T06:00:00-03:00"


@pytest.mark.parametrize(
    ("before", "after", "before_slot", "after_slot", "elapsed_hours"),
    (
        (
            datetime(2026, 3, 8, 0, 30, tzinfo=ZoneInfo("America/New_York")),
            datetime(2026, 3, 8, 6, 0, tzinfo=ZoneInfo("America/New_York")),
            "source-campaign:2026-03-08T00:00:00-05:00",
            "source-campaign:2026-03-08T06:00:00-04:00",
            5,
        ),
        (
            datetime(2026, 11, 1, 0, 30, tzinfo=ZoneInfo("America/New_York")),
            datetime(2026, 11, 1, 6, 0, tzinfo=ZoneInfo("America/New_York")),
            "source-campaign:2026-11-01T00:00:00-04:00",
            "source-campaign:2026-11-01T06:00:00-05:00",
            7,
        ),
    ),
)
def test_interval_slots_follow_local_timer_boundaries_across_dst(
    before: datetime,
    after: datetime,
    before_slot: str,
    after_slot: str,
    elapsed_hours: int,
) -> None:
    assert latest_interval_slot(
        before, timezone_name="America/New_York"
    ) == before_slot
    assert latest_interval_slot(after, timezone_name="America/New_York") == after_slot
    assert before_slot != after_slot
    assert (after.astimezone(UTC) - before.astimezone(UTC)).total_seconds() == (
        elapsed_hours - 0.5
    ) * 3600


@pytest.mark.parametrize("interval_hours", [0, -6, 5, 7, 25, True])
def test_interval_slot_rejects_invalid_intervals(interval_hours: int) -> None:
    with pytest.raises(ValueError, match="interval_hours"):
        latest_interval_slot(datetime(2026, 9, 28, 9, tzinfo=UTC), interval_hours=interval_hours)


def test_interval_slot_requires_timezone_aware_input() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        latest_interval_slot(datetime(2026, 9, 28, 9))
