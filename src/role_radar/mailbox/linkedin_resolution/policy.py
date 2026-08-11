"""Pure URL and redirect policy for F9.1."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import SplitResult, urljoin, urlsplit

from role_radar.discovery.contracts import GreenhouseOfficialCandidate, LeverOfficialCandidate
from role_radar.discovery.url_classifier import classify_url
from role_radar.mailbox.linkedin_resolution.contracts import FinalATS

POLICY_VERSION = "linkedin-head-resolution-v1"
LINKEDIN_HOSTS = frozenset({"ar.linkedin.com", "www.linkedin.com"})
GREENHOUSE_HOSTS = frozenset({"boards.greenhouse.io", "job-boards.greenhouse.io"})
LEVER_HOSTS = frozenset({"jobs.lever.co", "jobs.eu.lever.co"})
KNOWN_ATS_HOSTS = GREENHOUSE_HOSTS | LEVER_HOSTS
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REQUESTS = 3
MAX_REDIRECTS = 2
MAX_URL_LENGTH = 2048
MAX_LOCATION_LENGTH = 2048


class ResolutionPolicyError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class LinkedInTarget:
    url: str = field(repr=False)
    host: str


@dataclass(frozen=True, slots=True, repr=False)
class ATSTarget:
    url: str = field(repr=False)
    final_ats: FinalATS


def validate_linkedin_url(url: str) -> LinkedInTarget:
    parsed = _parse_url(url)
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or host is None
        or host not in LINKEDIN_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
    ):
        raise ResolutionPolicyError("allowlist_rejected")
    return LinkedInTarget(url, host)


def classify_location(current_url: str, location: str) -> LinkedInTarget | ATSTarget:
    if not isinstance(location, str) or not location or len(location) > MAX_LOCATION_LENGTH:
        raise ResolutionPolicyError("location_invalid")
    if any(ord(char) < 32 for char in location):
        raise ResolutionPolicyError("location_invalid")
    try:
        location.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ResolutionPolicyError("location_invalid") from exc
    if "\\" in location or "%" in location:
        raise ResolutionPolicyError("location_invalid")
    try:
        resolved = urljoin(current_url, location)
        parsed = _parse_url(resolved)
    except ResolutionPolicyError:
        raise
    except (TypeError, ValueError) as exc:
        raise ResolutionPolicyError("location_invalid") from exc
    host = parsed.hostname
    if host in LINKEDIN_HOSTS:
        return validate_linkedin_url(resolved)
    if host in KNOWN_ATS_HOSTS:
        return _classify_ats(resolved, parsed)
    raise ResolutionPolicyError("allowlist_rejected")


def _classify_ats(url: str, parsed: SplitResult) -> ATSTarget:
    if parsed.hostname not in GREENHOUSE_HOSTS and parsed.hostname not in LEVER_HOSTS:
        raise ResolutionPolicyError("ats_unsupported")
    candidate = classify_url(url)
    if isinstance(candidate, GreenhouseOfficialCandidate):
        if candidate.job_path is None:
            raise ResolutionPolicyError("ats_posting_missing")
        external_id = candidate.job_path.rsplit("/", 1)[-1]
        return ATSTarget(
            url,
            FinalATS("greenhouse", parsed.hostname or "", external_id),
        )
    if isinstance(candidate, LeverOfficialCandidate):
        if candidate.posting_id is None:
            raise ResolutionPolicyError("ats_posting_missing")
        if candidate.posting_id == "apply":
            raise ResolutionPolicyError("ats_posting_missing")
        return ATSTarget(
            url,
            FinalATS("lever", parsed.hostname or "", candidate.posting_id),
        )
    if parsed.hostname in GREENHOUSE_HOSTS or parsed.hostname in LEVER_HOSTS:
        raise ResolutionPolicyError("ats_invalid")
    raise ResolutionPolicyError("allowlist_rejected")


def _parse_url(url: str) -> SplitResult:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise ResolutionPolicyError("url_invalid")
    if any(ord(char) < 32 for char in url):
        raise ResolutionPolicyError("url_invalid")
    try:
        url.encode("ascii")
        parsed = urlsplit(url)
        _ = parsed.port
    except (UnicodeEncodeError, ValueError) as exc:
        raise ResolutionPolicyError("url_invalid") from exc
    if parsed.netloc != parsed.netloc.casefold():
        raise ResolutionPolicyError("url_invalid")
    if "\\" in url or "%" in url:
        raise ResolutionPolicyError("url_invalid")
    if parsed.hostname is None:
        raise ResolutionPolicyError("url_invalid")
    if parsed.hostname.endswith("."):
        raise ResolutionPolicyError("url_invalid")
    return parsed
