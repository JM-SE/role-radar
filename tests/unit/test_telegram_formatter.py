from datetime import UTC, datetime

from role_radar.notifications.contracts import DigestCandidate
from role_radar.notifications.formatter import (
    ALERT_FORMATTER_VERSION,
    format_digest,
    format_digest_batches,
    utf16_units,
)


def test_formatter_escapes_dynamic_html_and_is_bounded() -> None:
    item = DigestCandidate(
        "job",
        "score",
        "deep",
        '<Senior & "safe">',
        "A < B",
        "Remote > now",
        "https://example.test/app?a=1&b=2",
        91,
        88,
        datetime.now(UTC),
        strengths=("Python <3",),
        gaps=("<script>alert(1)</script>",),
    )
    formatted = format_digest((item,))
    assert formatted is not None
    assert "&lt;Senior &amp; &quot;safe&quot;&gt;" in formatted.body
    assert "<script>" not in formatted.body
    assert 1 <= utf16_units(formatted.body) <= 4096


def test_alert_formatter_labels_detection_without_claiming_publication() -> None:
    item = DigestCandidate(
        "job",
        "score",
        None,
        "Platform Engineer",
        "Acme",
        "Remote Argentina",
        "https://example.test/app",
        91,
        88,
        datetime(2026, 1, 1, tzinfo=UTC),
        match_explanation="Role fit and Argentina work mode passed the profile rules.",
    )

    batch = format_digest_batches((item,), heading="New Role Radar matches")[0]

    assert ALERT_FORMATTER_VERSION == "telegram-match-alert-v1"
    assert "New Role Radar matches" in batch.body
    assert "Detected recently; publication date unavailable" in batch.body
    assert "Published" not in batch.body
    assert "Argentina work mode" in batch.body
