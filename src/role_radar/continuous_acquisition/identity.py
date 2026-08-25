"""Versioned strong identity derivation and conservative URL normalization."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from role_radar.continuous_acquisition.contracts import IDENTITY_POLICY_VERSION

_OFFICIAL_HOSTS = frozenset(
    {"boards.greenhouse.io", "job-boards.greenhouse.io", "jobs.lever.co", "jobs.eu.lever.co"}
)
_TRACKING_PARAMETERS = frozenset(
    {
        "gh_src",
        "source",
        "ref",
        "referrer",
        "utm_campaign",
        "utm_content",
        "utm_medium",
        "utm_source",
        "utm_term",
    }
)


@dataclass(frozen=True, slots=True)
class StrongIdentity:
    kind: str
    version: str
    value: str


def _normalize_url(url: str, *, application: bool) -> str | None:
    if not isinstance(url, str) or not url or any(char.isspace() for char in url):
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    host = parsed.hostname
    if (
        parsed.scheme.casefold() != "https"
        or host is None
        or host.casefold() not in _OFFICIAL_HOSTS
    ):
        return None
    if parsed.username or parsed.password or parsed.port:
        return None
    if parsed.fragment:
        return None
    query = urlencode(
        sorted(
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key.casefold() not in _TRACKING_PARAMETERS and not key.casefold().startswith("utm_")
        )
    )
    path = parsed.path.rstrip("/") or "/"
    # Application URLs are accepted only from the same fixed official origins.
    del application
    return urlunsplit(("https", host.casefold(), path, query, ""))


def normalize_official_posting_url(url: str | None) -> str | None:
    return _normalize_url(url or "", application=False)


def normalize_application_url(url: str | None) -> str | None:
    return _normalize_url(url or "", application=True)


def derive_strong_identities(
    *,
    source_key: str,
    external_id: str | None,
    posting_url: str | None,
    application_url: str | None,
) -> tuple[StrongIdentity, ...]:
    if not source_key:
        raise ValueError("invalid_identity")
    values: list[StrongIdentity] = []
    if external_id:
        values.append(
            StrongIdentity(
                "source_external_id", IDENTITY_POLICY_VERSION, f"{source_key}:{external_id}"
            )
        )
    posting = normalize_official_posting_url(posting_url)
    application = normalize_application_url(application_url)
    if posting:
        values.append(StrongIdentity("official_posting_url", IDENTITY_POLICY_VERSION, posting))
    if application and application != posting:
        values.append(
            StrongIdentity("allowlisted_application_url", IDENTITY_POLICY_VERSION, application)
        )
    if not values:
        raise ValueError("invalid_identity")
    return tuple(values)
