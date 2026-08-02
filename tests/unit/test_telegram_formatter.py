from datetime import UTC, datetime

from role_radar.notifications.contracts import DigestCandidate
from role_radar.notifications.formatter import format_digest, utf16_units


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
