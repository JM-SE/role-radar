from datetime import UTC, datetime

from role_radar.notifications.contracts import DigestCandidate
from role_radar.notifications.selection import select_top_digest
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


def test_selection_is_strict_and_deterministic() -> None:
    result = select_top_digest(
        [candidate(str(index), 80 + index) for index in range(7)] + [candidate("low", 74)]
    )
    assert [item.job_id for item in result.selected] == ["6", "5", "4", "3", "2"]
    assert ("low", "final_score_below_threshold") in result.exclusions


def test_url_policy_rejects_userinfo_and_non_https() -> None:
    assert canonical_application_url("https://user:pass@example.test/job") is None
    assert canonical_application_url("http://example.test/job") is None
    assert (
        canonical_application_url("https://example.test/job?q=1") == "https://example.test/job?q=1"
    )
