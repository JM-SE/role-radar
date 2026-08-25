"""Pure exact classifier for the two already-supported official ATS origins."""

import re
from typing import Literal
from urllib.parse import urlsplit

from role_radar.discovery.contracts import (
    ClassifiedCandidate,
    GreenhouseOfficialCandidate,
    LeverOfficialCandidate,
    RejectedCandidate,
    UnknownCandidate,
)

_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_POSTING = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,255}$")
_GH_HOSTS = {"boards.greenhouse.io", "job-boards.greenhouse.io"}
_LEVER_HOSTS: dict[str, Literal["global", "eu"]] = {
    "jobs.lever.co": "global",
    "jobs.eu.lever.co": "eu",
}
_RESERVED = {"jobs", "job-boards", "login", "auth", "account", "unsubscribe", "apply"}


def classify_url(url: str) -> ClassifiedCandidate:
    if not isinstance(url, str) or not url or any(ord(char) < 32 for char in url):
        return RejectedCandidate("control_character")
    try:
        url.encode("ascii")
    except UnicodeEncodeError:
        return RejectedCandidate("non_ascii")
    if "\\" in url or "%" in url:
        return RejectedCandidate("ambiguous_encoding")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return RejectedCandidate("invalid_url")
    if parsed.scheme != "https" or host is None:
        return RejectedCandidate("https_required")
    if parsed.username is not None or parsed.password is not None or port is not None:
        return RejectedCandidate("userinfo_or_port")
    if parsed.netloc != parsed.netloc.casefold():
        return RejectedCandidate("host_must_be_lowercase")
    if parsed.query or parsed.fragment:
        return RejectedCandidate("query_or_fragment")
    if host != host.casefold() or (host not in _GH_HOSTS and host not in _LEVER_HOSTS):
        return UnknownCandidate("unsupported_host")
    segments = parsed.path.split("/")
    if not parsed.path.startswith("/") or any(not segment for segment in segments[1:]):
        return RejectedCandidate("invalid_path")
    clean = segments[1:]
    if any(segment in {".", ".."} for segment in clean):
        return RejectedCandidate("path_traversal")
    if host in _GH_HOSTS:
        if not clean or not _TOKEN.fullmatch(clean[0]) or clean[0] in _RESERVED:
            return RejectedCandidate("invalid_greenhouse_board")
        if len(clean) == 1:
            job_path = None
        elif len(clean) == 3 and clean[1] == "jobs" and _POSTING.fullmatch(clean[2]):
            job_path = "/".join(clean)
        else:
            return RejectedCandidate("unsupported_greenhouse_path")
        return GreenhouseOfficialCandidate(f"https://{host}/{'/'.join(clean)}", clean[0], job_path)
    if not clean or not _TOKEN.fullmatch(clean[0]) or clean[0] in _RESERVED:
        return RejectedCandidate("invalid_lever_site")
    if len(clean) == 1:
        posting_id = None
    elif (
        len(clean) in {2, 3}
        and _POSTING.fullmatch(clean[1])
        and (len(clean) == 2 or clean[2] == "apply")
    ):
        posting_id = clean[1]
    else:
        return RejectedCandidate("unsupported_lever_path")
    return LeverOfficialCandidate(
        f"https://{host}/{'/'.join(clean)}", clean[0], _LEVER_HOSTS[host], posting_id
    )


def classify(url: str) -> ClassifiedCandidate:
    """Compatibility spelling for the pure classifier seam."""
    return classify_url(url)


class UrlClassifier:
    """Named seam kept for callers that prefer dependency injection."""

    @staticmethod
    def classify(url: str) -> ClassifiedCandidate:
        return classify_url(url)
