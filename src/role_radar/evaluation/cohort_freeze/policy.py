"""Versioned F10.1C policy and pure boundary/content validators."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from role_radar.evaluation.snapshot_store import canonical_json_bytes

BOUNDARY_RUN_ID = "d19ce3d0-4e87-448d-a510-39be39b3fef6"
SELECTION_PROTOCOL = "f10.1c-selection-v1"
MATERIALIZATION_PROTOCOL = "f10.1c-materialization-v1"
PREVIEW_SCHEMA = "f10.1c-preview-v1"
SNAPSHOT_SCHEMA = "f10.1c-snapshot-v1"
EXTERNAL_MANIFEST_SCHEMA = "f10.1c-external-manifest-v1"
TARGET_COUNT = 50
SNAPSHOT_ROOT = "/opt/role-radar/data/evaluation/f10.1c"
BASELINE_PROFILE_ID = "e4aec18c-90fa-455a-ae3e-9e4655223683"
BASELINE_PROFILE_VERSION = 2
BASELINE_PROFILE_SCHEMA = 1
BASELINE_PROFILE_SCHEMA_VERSION = BASELINE_PROFILE_SCHEMA
BASELINE_PROFILE_SHA256 = "609601723c1510a2908fde05dac58378b5ad96e6ca9a6a1384aba5a3078a5a3b"
ALEMBIC_HEAD = "f101b_continuous"

CONTENT_LIMITS = {
    "title": 255,
    "company": 255,
    "location": 255,
    "description": 256 * 1024,
    "application_url": 2048,
}
TERMINAL_CODES = (
    "run_not_terminal",
    "run_operation_inconsistent",
    "operation_not_accepted",
    "source_snapshot_invalid",
    "run_snapshot_inconsistent",
    "freshness_provenance_missing",
    "freshness_provenance_invalid",
    "job_missing",
    "strong_identity_missing",
    "strong_identity_inconsistent",
    "job_content_missing",
    "job_content_oversized",
    "job_content_not_utf8",
    "job_url_invalid",
)
IGNORED_CODES = (
    "duplicate_link_ignored",
    "non_first_created_link_ignored",
    "eligible_after_first_50",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_time(value: datetime | str) -> str:
    """Canonical RFC3339 UTC with exactly six fractional digits."""

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        parsed = datetime.fromisoformat(raw)
    else:
        raise ValueError("timestamp_invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def source_snapshot_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        isinstance(value.get("source_id"), str)
        and bool(value["source_id"].strip())
        and isinstance(value.get("source_key"), str)
        and bool(value["source_key"].strip())
        and isinstance(value.get("type"), str)
        and bool(value["type"].strip())
        and isinstance(value.get("revision"), int)
        and not isinstance(value["revision"], bool)
        and value["revision"] >= 1
    )


def content_reason(candidate: Any) -> str | None:
    for name in ("title", "company", "description"):
        value = getattr(candidate, name, None)
        if not isinstance(value, str) or not value.strip():
            return "job_content_missing"
    for name, limit in CONTENT_LIMITS.items():
        value = getattr(candidate, name, None)
        if (
            value is not None
            and isinstance(value, str)
            and len(value.encode("utf-8", "surrogatepass")) > limit
        ):
            return "job_content_oversized"
    for name in ("title", "company", "location", "description", "application_url"):
        value = getattr(candidate, name, None)
        if value is not None:
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError:
                return "job_content_not_utf8"
            if "\x00" in value or any(ord(char) < 32 and char not in "\t\n\r" for char in value):
                return "job_content_not_utf8"
    url = getattr(candidate, "application_url", None)
    if url is not None:
        if not isinstance(url, str) or len(url.encode("utf-8")) > CONTENT_LIMITS["application_url"]:
            return "job_url_invalid"
        try:
            parsed = urlsplit(url)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.username is not None
                or parsed.password is not None
                or not parsed.hostname
            ):
                return "job_url_invalid"
        except ValueError:
            return "job_url_invalid"
        if any(char.isspace() or ord(char) < 32 for char in url):
            return "job_url_invalid"
    return None


def profile_sha256(profile_json: Any) -> str:
    return canonical_hash(profile_json)


def acknowledgement(preview_sha256: str) -> str:
    if HEX64.fullmatch(preview_sha256) is None:
        raise ValueError("preview_hash_invalid")
    return (
        f"FREEZE F10.1C preview_sha256={preview_sha256} profile_sha256="
        f"{BASELINE_PROFILE_SHA256} protocol={SELECTION_PROTOCOL} count={TARGET_COUNT}"
    )


def validate_acknowledgement(value: str, preview_sha256: str) -> bool:
    return value == acknowledgement(preview_sha256)


__all__ = [name for name in globals() if name.isupper()] + [
    "acknowledgement",
    "canonical_hash",
    "canonical_time",
    "content_reason",
    "profile_sha256",
    "source_snapshot_valid",
    "validate_acknowledgement",
]
