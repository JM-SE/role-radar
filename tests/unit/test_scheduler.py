from datetime import UTC, datetime

from role_radar.scheduler import latest_slot


def test_latest_slot_handles_before_and_after_daily_anchor() -> None:
    before = latest_slot(
        datetime(2026, 8, 2, 7, 59, tzinfo=UTC),
        schedule_id="daily",
        hour_utc=8,
        minute_utc=0,
    )
    after = latest_slot(
        datetime(2026, 8, 2, 8, 0, 1, tzinfo=UTC),
        schedule_id="daily",
        hour_utc=8,
        minute_utc=0,
    )
    assert before.endswith("2026-08-01T08:00:00Z")
    assert after.endswith("2026-08-02T08:00:00Z")
