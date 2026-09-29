"""Pure complete delivery selection rules."""

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from role_radar.notifications.contracts import DigestCandidate
from role_radar.notifications.url_policy import canonical_application_url

FIRST_SEEN_MAX_AGE = timedelta(hours=24)
PUBLISHED_MAX_AGE = timedelta(days=14)


@dataclass(frozen=True, slots=True)
class DeliverySelectionResult:
    selected: tuple[DigestCandidate, ...]
    exclusions: tuple[tuple[str, str], ...]


def select_delivery_candidates(
    candidates: list[DigestCandidate] | tuple[DigestCandidate, ...],
    *,
    now: datetime | None = None,
) -> DeliverySelectionResult:
    """Select only actionable, fresh offers and order them deterministically."""
    current = _as_utc(now or datetime.now(UTC))
    if current is None:
        raise ValueError("selection_clock_invalid")
    valid: list[DigestCandidate] = []
    exclusions: list[tuple[str, str]] = []
    for candidate in candidates:
        freshness_error = freshness_exclusion(candidate, now=current)
        if freshness_error is not None:
            exclusions.append((candidate.job_id, freshness_error))
            continue
        canonical = canonical_application_url(candidate.application_url)
        if canonical is None:
            exclusions.append((candidate.job_id, "invalid_application_url"))
        else:
            valid.append(replace(candidate, application_url=canonical))
    valid.sort(
        key=lambda item: (
            -item.final_score,
            -item.preliminary_score,
            -_timestamp(item),
            item.job_id,
        )
    )
    return DeliverySelectionResult(tuple(valid), tuple(exclusions))


def freshness_exclusion(candidate: DigestCandidate, *, now: datetime) -> str | None:
    """Return a stable exclusion reason for timestamps/status that cannot alert."""
    current = _as_utc(now)
    first_seen = _as_utc(candidate.first_seen_at)
    if current is None or first_seen is None:
        return "first_seen_unknown"
    if first_seen > current:
        return "first_seen_in_future"
    if current - first_seen > FIRST_SEEN_MAX_AGE:
        return "not_recently_detected"
    if candidate.status not in {"new", "active"}:
        return "job_not_open"
    expires_at = _as_utc(candidate.expires_at)
    if candidate.expires_at is not None and expires_at is None:
        return "expiry_timestamp_invalid"
    if expires_at is not None and expires_at <= current:
        return "job_expired"
    published_at = _as_utc(candidate.published_at)
    if candidate.published_at is not None and published_at is None:
        return "publication_timestamp_invalid"
    if published_at is not None:
        if published_at > current:
            return "publication_date_in_future"
        if current - published_at > PUBLISHED_MAX_AGE:
            return "publication_too_old"
    return None


def _as_utc(value: datetime | None) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    # SQLite drops tzinfo for SQLAlchemy DateTime(timezone=True); persisted Role
    # Radar timestamps are UTC by contract, so restore UTC for those values.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _timestamp(candidate: DigestCandidate) -> float:
    value = _as_utc(candidate.first_seen_at)
    return value.timestamp() if value is not None else 0.0
