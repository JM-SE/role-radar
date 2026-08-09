"""Offline hostile-input coverage for bounded mailbox MIME parsing."""

import pytest

from role_radar.mailbox.mime_parser import MAX_RFC822_BYTES, MimeLimitError, parse_rfc822


def test_plain_and_html_are_bounded_and_remote_resources_are_not_loaded() -> None:
    raw = (
        b"From: alerts@example.com\n"
        b"Authentication-Results: mx; dkim=pass\n"
        b"Content-Type: text/html; charset=utf-8\n\n"
        b"<script>https://secret.invalid</script><a href=\"https://example.com/job\">job</a>"
    )
    parsed = parse_rfc822(raw)
    assert parsed.auth_evidence == "pass"
    assert parsed.urls == ("https://example.com/job",)
    assert "secret.invalid" not in parsed.text


def test_rfc822_cap_plus_one_is_terminal_and_not_truncated() -> None:
    with pytest.raises(MimeLimitError) as error:
        parse_rfc822(b"From: a@example.com\n\n" + b"x" * (MAX_RFC822_BYTES + 1))
    assert error.value.code == "mime_limit"


def test_attachment_is_rejected_instead_of_decoded() -> None:
    raw = (
        b"From: a@example.com\nMIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=x\n\n"
        b"--x\nContent-Type: text/plain\n\nhello\n"
        b"--x\nContent-Type: application/zip\nContent-Disposition: attachment\n\nbytes\n--x--"
    )
    with pytest.raises(MimeLimitError) as error:
        parse_rfc822(raw)
    assert error.value.code == "unsupported"
