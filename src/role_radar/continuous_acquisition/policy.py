"""Pure freshness, budget, conservation and result aggregation policies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from role_radar.continuous_acquisition.contracts import (
    ACQUISITION_POLICY_VERSION,
    FRESHNESS_POLICY_VERSION,
    AcquisitionRunResult,
    AcquisitionRunState,
    AcquisitionSourceOutcome,
    Budget,
    BudgetCounter,
    FreshnessDecision,
    JobCounters,
    RecencyProvenance,
    RejectionCode,
)
from role_radar.domain.dto import RawJob

FRESHNESS_WINDOW = timedelta(days=14)


def _as_utc(value: datetime) -> datetime | None:
    if value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(UTC)


def parse_provider_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return _as_utc(parsed)


def provider_recency(raw: RawJob) -> tuple[datetime | None, str | None]:
    """Return only provider-owned recency; collected_at is intentionally ignored."""
    family = raw.source.casefold()
    data = raw.structured_data
    if family == "jobicy":
        if raw.published_at is not None:
            return _as_utc(raw.published_at), "published_at"
        value = data.get("pubDate", data.get("published_at"))
        return parse_provider_timestamp(value), "published_at" if value is not None else None
    if family == "greenhouse":
        value = data.get("updated_at")
        return parse_provider_timestamp(value), "provider_updated_at_proxy" if value is not None else None
    if family == "lever":
        value = data.get("createdAt")
        return parse_provider_timestamp(value), "provider_created_at" if value is not None else None
    return None, None


def freshness_decision(
    raw: RawJob, *, as_of_utc: datetime, window: timedelta = FRESHNESS_WINDOW
) -> FreshnessDecision:
    """Strict inclusive cutoff, inclusive ``as_of`` boundary, no future tolerance."""
    as_of = _as_utc(as_of_utc)
    if as_of is None:
        raise ValueError("as_of_utc must be timezone-aware")
    cutoff = as_of - window
    recency, semantic = provider_recency(raw)
    if recency is None:
        has_provider_value = (
            (raw.source.casefold() == "greenhouse" and "updated_at" in raw.structured_data)
            or (raw.source.casefold() == "lever" and "createdAt" in raw.structured_data)
            or (raw.source.casefold() == "jobicy" and (raw.published_at is not None or "pubDate" in raw.structured_data or "published_at" in raw.structured_data))
        )
        code = RejectionCode.INVALID_RECENCY.value if has_provider_value else RejectionCode.MISSING_RECENCY.value
        return FreshnessDecision(False, code, None, cutoff)
    if semantic is None:
        return FreshnessDecision(False, RejectionCode.INVALID_RECENCY.value, None, cutoff)
    if recency < cutoff:
        return FreshnessDecision(False, RejectionCode.STALE.value, None, cutoff)
    if recency > as_of:
        return FreshnessDecision(False, RejectionCode.FUTURE.value, None, cutoff)
    status = str(raw.structured_data.get("status", "")).casefold()
    if status in {"closed", "expired", "archived", "filled"}:
        return FreshnessDecision(False, RejectionCode.CLOSED.value, None, cutoff)
    expires = raw.structured_data.get("expires_at")
    expires_at = parse_provider_timestamp(expires)
    if expires_at is not None and expires_at <= as_of:
        return FreshnessDecision(False, RejectionCode.EXPIRED.value, None, cutoff)
    return FreshnessDecision(
        True,
        None,
        RecencyProvenance(recency, semantic, FRESHNESS_POLICY_VERSION),
        cutoff,
    )


def assert_conservation(counters: JobCounters) -> None:
    if not counters.conserved():
        raise ValueError(
            "result conservation violated: observed must equal "
            "created+duplicate+stale+invalid+conflict"
        )


def reserve_budget(current: BudgetCounter, amount: int, limit: int) -> BudgetCounter:
    return current.reserve(amount, limit)


def aggregate_outcomes(
    outcomes: tuple[AcquisitionSourceOutcome, ...], *, counters: JobCounters | None = None
) -> AcquisitionRunResult:
    """Exhaustive primary ATS aggregation; optional providers are not represented here."""
    aggregate = counters or JobCounters()
    for outcome in outcomes:
        aggregate = aggregate.add(outcome.counters)
    assert_conservation(aggregate)
    if any(item.state.value == "indeterminate" for item in outcomes):
        state = AcquisitionRunState.INDETERMINATE
    elif not outcomes or all(not item.usable for item in outcomes):
        state = AcquisitionRunState.FAILED
    elif any(item.state.value in {"failed", "truncated"} for item in outcomes) and any(item.usable for item in outcomes):
        state = AcquisitionRunState.COMPLETED_PARTIAL
    elif any(item.state.value in {"failed", "truncated"} for item in outcomes):
        state = AcquisitionRunState.FAILED
    elif aggregate.created + aggregate.duplicate > 0:
        state = AcquisitionRunState.COMPLETED
    else:
        state = AcquisitionRunState.COMPLETED_EMPTY
    return AcquisitionRunResult(
        state=state,
        new_jobs=aggregate.created,
        outcomes=outcomes,
        counters=aggregate,
        terminal_code="budget_exhausted" if any(item.continuation for item in outcomes) else None,
    )


def default_budget() -> Budget:
    return Budget(version=ACQUISITION_POLICY_VERSION)
