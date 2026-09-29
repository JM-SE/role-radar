from dataclasses import replace
from datetime import UTC, datetime, timedelta

from role_radar.notifications.contracts import DigestCandidate
from role_radar.notifications.selection import select_delivery_candidates
from role_radar.notifications.url_policy import canonical_application_url


def candidate(
    job_id: str, score: int, *, url: str = "https://jobs.example.test/app"
) -> DigestCandidate:
    return DigestCandidate(
        job_id,
        f"score-{job_id}",
        f"deep-{job_id}",
        job_id,
        "Acme",
        None,
        url,
        score,
        score,
        datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_selection_is_complete_and_deterministic() -> None:
    result = select_delivery_candidates(
        [candidate(str(index), 80 + index) for index in range(7)] + [candidate("low", 74)],
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert [item.job_id for item in result.selected] == ["6", "5", "4", "3", "2", "1", "0", "low"]
    assert result.exclusions == ()


def test_selection_enforces_detection_publication_and_expiry_windows() -> None:
    now = datetime(2026, 1, 20, 12, tzinfo=UTC)
    values = [
        candidate("fresh-no-publish-date", 90),
        candidate("inclusive-age-boundary", 90),
        candidate("old-detection", 90),
        candidate("future-detection", 90),
        candidate("old-publication", 90),
        candidate("future-publication", 90),
        candidate("expired", 90),
        candidate("closed", 90),
    ]
    values[0] = replace(values[0], first_seen_at=now)
    values[1] = replace(
        values[1],
        first_seen_at=now - timedelta(hours=24),
        published_at=now - timedelta(days=14),
    )
    values[2] = replace(values[2], first_seen_at=now - timedelta(hours=24, seconds=1))
    values[3] = replace(values[3], first_seen_at=now + timedelta(seconds=1))
    values[4] = replace(
        values[4],
        first_seen_at=now,
        published_at=now - timedelta(days=14, seconds=1),
    )
    values[5] = replace(values[5], first_seen_at=now, published_at=now + timedelta(seconds=1))
    values[6] = replace(values[6], first_seen_at=now, expires_at=now)
    values[7] = replace(values[7], first_seen_at=now, status="expired")

    result = select_delivery_candidates(values, now=now)

    assert [item.job_id for item in result.selected] == [
        "fresh-no-publish-date",
        "inclusive-age-boundary",
    ]
    assert dict(result.exclusions) == {
        "old-detection": "not_recently_detected",
        "future-detection": "first_seen_in_future",
        "old-publication": "publication_too_old",
        "future-publication": "publication_date_in_future",
        "expired": "job_expired",
        "closed": "job_not_open",
    }


def test_selection_rejects_missing_detection_timestamp() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    result = select_delivery_candidates(
        [replace(candidate("missing", 90), first_seen_at=None)], now=now
    )
    assert result.selected == ()
    assert result.exclusions == (("missing", "first_seen_unknown"),)


def test_url_policy_rejects_userinfo_and_non_https() -> None:
    assert canonical_application_url("https://user:pass@example.test/job") is None
    assert canonical_application_url("http://example.test/job") is None
    assert (
        canonical_application_url("https://example.test/job?q=1") == "https://example.test/job?q=1"
    )
