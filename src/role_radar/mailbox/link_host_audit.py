"""Pure, fail-closed host and URL-shape audit for LinkedIn intake."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from role_radar.discovery.contracts import GreenhouseOfficialCandidate, LeverOfficialCandidate
from role_radar.discovery.url_classifier import classify_url

SCHEMA_VERSION = "linkedin-link-host-audit-v1"
MAX_URLS = 100
MAX_HOSTS = 20
MAX_HOST_LENGTH = 253
MAX_URL_LENGTH = 2048
GREENHOUSE_HOSTS = frozenset({"boards.greenhouse.io", "job-boards.greenhouse.io"})
LEVER_HOSTS = frozenset({"jobs.lever.co", "jobs.eu.lever.co"})
TERMINAL_CODES = frozenset(
    {
        "live_ack_required",
        "empty",
        "source_not_found",
        "source_must_be_disabled",
        "config",
        "credentials",
        "auth",
        "connection",
        "timeout",
        "bye",
        "protocol",
        "label_not_found",
        "label_not_exact",
        "message_limit",
        "mime_limit",
        "malformed",
        "unsupported",
        "template_drift",
        "review",
        "parser_mismatch",
        "unsafe_url",
        "url_limit",
        "host_limit",
    }
)

_HOST_LABEL = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


@dataclass(frozen=True, slots=True)
class LinkHostSummary:
    host: str
    url_count: int
    https_count: int
    query_present_count: int
    fragment_present_count: int
    direct_ats_greenhouse_count: int
    direct_ats_lever_count: int
    linkedin_family: bool
    unknown: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "url_count": self.url_count,
            "https_count": self.https_count,
            "query_present_count": self.query_present_count,
            "fragment_present_count": self.fragment_present_count,
            "direct_ats_greenhouse_count": self.direct_ats_greenhouse_count,
            "direct_ats_lever_count": self.direct_ats_lever_count,
            "linkedin_family": self.linkedin_family,
            "unknown": self.unknown,
        }


@dataclass(frozen=True, slots=True)
class LinkHostAudit:
    validated: bool
    total_url_count: int
    distinct_host_count: int
    host_summaries: tuple[LinkHostSummary, ...]
    terminal_code: str | None = None


@dataclass
class _HostCounters:
    url_count: int = 0
    https_count: int = 0
    query_present_count: int = 0
    fragment_present_count: int = 0
    direct_ats_greenhouse_count: int = 0
    direct_ats_lever_count: int = 0


def audit_link_hosts(urls: tuple[str, ...]) -> LinkHostAudit:
    """Aggregate URL shape facts without retaining URL values or doing I/O."""
    if len(urls) > MAX_URLS:
        return _failure("url_limit")
    counters: dict[str, _HostCounters] = {}
    for url in urls:
        parsed, host = _parse_url(url)
        if parsed is None or host is None:
            return _failure("unsafe_url")
        if host not in counters:
            if len(counters) >= MAX_HOSTS:
                return _failure("host_limit")
            counters[host] = _HostCounters()
        item = counters[host]
        item.url_count += 1
        item.https_count += parsed.scheme.lower() == "https"
        item.query_present_count += bool(parsed.query)
        item.fragment_present_count += bool(parsed.fragment)
        classified = classify_url(url)
        if isinstance(classified, GreenhouseOfficialCandidate):
            item.direct_ats_greenhouse_count += 1
        elif isinstance(classified, LeverOfficialCandidate):
            item.direct_ats_lever_count += 1
    summaries = tuple(
        _summary(host, item) for host, item in sorted(counters.items(), key=lambda pair: pair[0])
    )
    return LinkHostAudit(True, len(urls), len(summaries), summaries)


def _parse_url(url: str) -> tuple[SplitResult, str] | tuple[None, None]:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        return None, None
    if any(ord(char) < 32 for char in url):
        return None, None
    try:
        url.encode("ascii")
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        return None, None
    if (
        host is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
    ):
        return None, None
    host = host.rstrip(".").lower()
    if (
        not host
        or len(host) > MAX_HOST_LENGTH
        or "xn--" in host
        or _HOST_LABEL.fullmatch(host) is None
    ):
        return None, None
    return parsed, host


def _summary(host: str, counters: _HostCounters) -> LinkHostSummary:
    linkedin_family = host == "linkedin.com" or host.endswith(".linkedin.com")
    known_ats_host = host in GREENHOUSE_HOSTS or host in LEVER_HOSTS
    return LinkHostSummary(
        host,
        counters.url_count,
        counters.https_count,
        counters.query_present_count,
        counters.fragment_present_count,
        counters.direct_ats_greenhouse_count,
        counters.direct_ats_lever_count,
        linkedin_family,
        not linkedin_family and not known_ats_host,
    )


def _failure(code: str) -> LinkHostAudit:
    return LinkHostAudit(False, 0, 0, (), code if code in TERMINAL_CODES else "unsafe_url")
