"""Provider recency and liveness policy, kept pure for exhaustive tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from role_radar.evaluation.controlled_acquisition.contracts import Observation


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def provider_recency(
    family: str, structured_data: dict[str, Any], published_at: datetime | None = None
) -> tuple[datetime | None, str | None]:
    if family == "jobicy":
        return published_at or parse_timestamp(structured_data.get("published")), "published_at"
    if family == "greenhouse":
        return parse_timestamp(structured_data.get("updated_at")), "provider_updated_at_proxy"
    if family == "lever":
        return parse_timestamp(structured_data.get("createdAt")), "provider_created_at"
    return None, None


def eligibility(
    observation: Observation,
    *,
    cutoff_utc: datetime,
    as_of_utc: datetime,
    future_tolerance_seconds: int = 300,
) -> str | None:
    timestamp = observation.provider_recency_at
    if timestamp is None:
        return "freshness_timestamp_missing"
    timestamp = timestamp.astimezone(UTC)
    if timestamp < cutoff_utc.astimezone(UTC):
        return "freshness_before_cutoff"
    if timestamp > as_of_utc.astimezone(UTC) + timedelta(seconds=future_tolerance_seconds):
        return "freshness_future"
    if not observation.official_listing:
        return "not_current_official_listing"
    status = (observation.provider_status or "").strip().lower()
    if status in {"closed", "expired", "archived", "filled"}:
        return "provider_closed"
    if observation.expires_at is not None and observation.expires_at.astimezone(
        UTC
    ) <= as_of_utc.astimezone(UTC):
        return "expired_at_selection_time"
    return None
