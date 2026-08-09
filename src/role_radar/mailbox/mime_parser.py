"""Pure, bounded RFC822/MIME parsing.

This module never opens a URL, renders HTML, stores raw mail, or invokes a
vendor parser.  Limits are constants owned by the application.
"""

from __future__ import annotations

import re
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any

from role_radar.mailbox.contracts import BoundedMailboxMessage, MailboxErrorCode

MAX_RFC822_BYTES = 2 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 200
MAX_PARTS = 50
MAX_DEPTH = 10
MAX_TEXT_BYTES = 512 * 1024
MAX_HTML_BYTES = 256 * 1024
MAX_URLS = 100
MAX_URL_LENGTH = 2048

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


class MimeLimitError(ValueError):
    def __init__(self, code: str = MailboxErrorCode.MIME_LIMIT.value) -> None:
        self.code = code
        super().__init__(code)


class _SafeHtml(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.urls: list[str] = []
        self._blocked = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript", "iframe", "object", "embed"}:
            self._blocked += 1
            return
        if self._blocked:
            return
        for key, value in attrs:
            if key.lower() == "href" and value is not None:
                self.urls.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "iframe", "object", "embed"}:
            self._blocked = max(0, self._blocked - 1)

    def handle_data(self, data: str) -> None:
        if not self._blocked:
            self.text.append(data)


def parse_rfc822(data: bytes) -> BoundedMailboxMessage:
    if len(data) > MAX_RFC822_BYTES:
        raise MimeLimitError()
    separator = data.find(b"\n\n")
    separator_crlf = data.find(b"\r\n\r\n")
    candidates = [item for item in (separator, separator_crlf) if item >= 0]
    header_bytes = data if not candidates else data[: min(candidates)]
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise MimeLimitError()
    if sum(
        1 for line in header_bytes.splitlines() if line and line[:1] not in b" \t"
    ) > MAX_HEADERS:
        raise MimeLimitError()
    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except (ValueError, IndexError, UnicodeError) as exc:
        raise MimeLimitError(MailboxErrorCode.MALFORMED.value) from exc
    if message.defects:
        raise MimeLimitError(MailboxErrorCode.MALFORMED.value)

    parts = 0
    texts: list[str] = []
    htmls: list[str] = []
    raw_urls: list[str] = []

    def visit(part: Any, depth: int) -> None:
        nonlocal parts
        parts += 1
        if parts > MAX_PARTS or depth > MAX_DEPTH:
            raise MimeLimitError()
        is_multipart = part.is_multipart()
        if is_multipart:
            payload = part.iter_parts()
            for child in payload:
                visit(child, depth + 1)
            return
        disposition = part.get_content_disposition()
        content_type = str(part.get_content_type()).lower()
        if disposition == "attachment" or content_type not in {"text/plain", "text/html"}:
            raise MimeLimitError(MailboxErrorCode.UNSUPPORTED.value)
        charset = part.get_content_charset()
        if charset is not None and charset.lower() not in {
            "utf-8",
            "utf8",
            "us-ascii",
            "iso-8859-1",
            "latin-1",
        }:
            raise MimeLimitError(MailboxErrorCode.MALFORMED.value)
        try:
            value = part.get_content()
        except (LookupError, UnicodeError, ValueError) as exc:
            raise MimeLimitError(MailboxErrorCode.MALFORMED.value) from exc
        if not isinstance(value, str):
            raise MimeLimitError(MailboxErrorCode.MALFORMED.value)
        encoded_size = len(value.encode("utf-8"))
        if content_type == "text/html":
            if encoded_size > MAX_HTML_BYTES:
                raise MimeLimitError()
            htmls.append(value)
            parser = _SafeHtml()
            try:
                parser.feed(value)
                parser.close()
            except (ValueError, AssertionError) as exc:
                raise MimeLimitError(MailboxErrorCode.MALFORMED.value) from exc
            texts.append(" ".join(parser.text))
            raw_urls.extend(parser.urls)
        else:
            if encoded_size > MAX_TEXT_BYTES:
                raise MimeLimitError()
            texts.append(value)
            raw_urls.extend(_URL_RE.findall(value))

    visit(message, 0)
    text = "\n".join(texts)
    html = "\n".join(htmls)
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise MimeLimitError()
    urls = _bounded_urls(raw_urls)
    sender = parseaddr(str(message.get("From", "")))[1]
    domain = sender.rsplit("@", 1)[1].lower().strip(".") if "@" in sender else None
    list_id = str(message.get("List-ID", "")).strip().lower() or None
    list_id = list_id[:255] if list_id is not None else None
    auth = _auth_evidence(str(message.get("Authentication-Results", "")))
    subject = _decode_header(str(message.get("Subject", "")))[:255]
    return BoundedMailboxMessage(domain, list_id, auth, subject, text, html, tuple(urls))


def _bounded_urls(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        clean = value.rstrip(".,);]>")
        if len(clean) > MAX_URL_LENGTH:
            raise MimeLimitError()
        if clean not in result:
            result.append(clean)
        if len(result) > MAX_URLS:
            raise MimeLimitError()
    return result


def _decode_header(value: str) -> str:
    try:
        return str(make_header(decode_header(value)))
    except (UnicodeError, ValueError) as exc:
        raise MimeLimitError(MailboxErrorCode.MALFORMED.value) from exc


def _auth_evidence(value: str) -> str:
    lowered = value.lower()
    if not lowered:
        return "missing"
    passes = [name for name in ("dkim", "dmarc", "spf") if re.search(rf"\b{name}=pass\b", lowered)]
    if passes:
        return "pass"
    if any(
        re.search(rf"\b{name}=(fail|softfail|neutral)\b", lowered)
        for name in ("dkim", "dmarc", "spf")
    ):
        return "fail"
    return "ambiguous"
