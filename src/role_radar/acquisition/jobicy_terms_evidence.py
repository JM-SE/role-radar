"""Offline, root-managed Jobicy two-page evidence bundles."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

JOBICY_EVIDENCE_ROOT = Path("/etc/role-radar/evidence/jobicy")
TERMS_URL = "https://jobicy.com/terms-and-conditions"
RSS_URL = "https://jobicy.com/jobs-rss-feed"
BUNDLE_FORMAT_VERSION = "jobicy-terms-bundle-v1"
POLICY_VERSION = "jobicy-terms-v1"
MANIFEST_NAME = "manifest.json"
PAGE_NAMES = ("terms-and-conditions.html", "jobs-rss-feed.html")
MAX_MANIFEST_BYTES = 16 * 1024
MAX_PAGE_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class JobicyEvidenceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class JobicyPageEvidence:
    url: str
    retrieved_at: datetime
    sha256: str


@dataclass(frozen=True, slots=True)
class JobicyTermsEvidence:
    terms_sha256: str
    policy_version: str
    bundle_format_version: str
    pages: tuple[JobicyPageEvidence, JobicyPageEvidence]

    def __repr__(self) -> str:
        return "JobicyTermsEvidence(<verified metadata>)"


@dataclass(frozen=True, slots=True)
class EvidenceFilePolicy:
    owner_uid: int = 0
    group_gid: int | None = None
    directory_mode: int = 0o550
    file_mode: int = 0o440


def load_jobicy_terms_evidence(
    terms_sha256: str,
    *,
    root: str | os.PathLike[str] = JOBICY_EVIDENCE_ROOT,
    policy: EvidenceFilePolicy | None = None,
) -> JobicyTermsEvidence:
    if SHA256_RE.fullmatch(terms_sha256) is None:
        raise JobicyEvidenceError("terms_digest_invalid")
    selected = policy or EvidenceFilePolicy(group_gid=_role_radar_gid())
    root_path = Path(root)
    root_fd = child_fd = -1
    try:
        root_fd = _open_checked_dir(root_path, selected, root_fd=None)
        child_fd = os.open(
            terms_sha256,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        _check_stat(os.fstat(child_fd), selected, directory=True)
        names = {entry.name for entry in os.scandir(child_fd)}
        if names != {MANIFEST_NAME, *PAGE_NAMES}:
            raise JobicyEvidenceError("terms_bundle_format_mismatch")
        manifest = _read_json_file(child_fd, MANIFEST_NAME, selected, MAX_MANIFEST_BYTES)
        evidence = _validate_manifest(manifest, terms_sha256)
        hashes: list[str] = []
        for page_name in PAGE_NAMES:
            hashes.append(_hash_file(child_fd, page_name, selected, MAX_PAGE_BYTES))
        if tuple(hashes) != tuple(page.sha256 for page in evidence.pages):
            raise JobicyEvidenceError("terms_page_digest_mismatch")
        return evidence
    except JobicyEvidenceError:
        raise
    except FileNotFoundError as exc:
        raise JobicyEvidenceError("terms_bundle_missing") from exc
    except (OSError, json.JSONDecodeError, UnicodeError, TypeError, ValueError) as exc:
        raise JobicyEvidenceError("terms_bundle_insecure") from exc
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _validate_manifest(raw: Any, expected_digest: str) -> JobicyTermsEvidence:
    if not isinstance(raw, dict) or set(raw) != {
        "bundle_format_version", "pages", "policy_version"
    }:
        raise JobicyEvidenceError("terms_manifest_invalid")
    if raw["bundle_format_version"] != BUNDLE_FORMAT_VERSION:
        raise JobicyEvidenceError("terms_bundle_format_mismatch")
    if raw["policy_version"] != POLICY_VERSION:
        raise JobicyEvidenceError("terms_policy_mismatch")
    pages = raw["pages"]
    if not isinstance(pages, list) or len(pages) != 2:
        raise JobicyEvidenceError("terms_manifest_invalid")
    expected = ((TERMS_URL, PAGE_NAMES[0]), (RSS_URL, PAGE_NAMES[1]))
    values: list[JobicyPageEvidence] = []
    for item, (url, _filename) in zip(pages, expected, strict=True):
        if not isinstance(item, dict) or set(item) != {"retrieved_at", "sha256", "url"}:
            raise JobicyEvidenceError("terms_manifest_invalid")
        if (
            item["url"] != url
            or not isinstance(item["sha256"], str)
            or SHA256_RE.fullmatch(item["sha256"]) is None
        ):
            raise JobicyEvidenceError(
                "terms_url_disallowed"
                if item.get("url") != url
                else "terms_manifest_invalid"
            )
        retrieved = _parse_zulu(item["retrieved_at"])
        values.append(JobicyPageEvidence(url, retrieved, item["sha256"]))
    canonical = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if canonical != _manifest_bytes_for_compare(raw):
        raise JobicyEvidenceError("terms_manifest_invalid")
    if hashlib.sha256(canonical).hexdigest() != expected_digest:
        raise JobicyEvidenceError("terms_manifest_digest_mismatch")
    assert len(values) == 2
    return JobicyTermsEvidence(
        expected_digest,
        cast(str, raw["policy_version"]),
        cast(str, raw["bundle_format_version"]),
        (values[0], values[1]),
    )


def _manifest_bytes_for_compare(raw: dict[str, Any]) -> bytes:
    # The loader stores this marker only while reading; the caller replaces it
    # with exact bytes through _read_json_file below.
    return json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _read_json_file(fd: int, name: str, policy: EvidenceFilePolicy, cap: int) -> dict[str, Any]:
    handle = _open_checked_file(fd, name, policy)
    try:
        data = _read_bounded(handle, cap)
    finally:
        os.close(handle)
    try:
        raw = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JobicyEvidenceError("terms_manifest_invalid") from exc
    canonical = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if data != canonical:
        raise JobicyEvidenceError("terms_manifest_invalid")
    return cast(dict[str, Any], raw)


def _hash_file(fd: int, name: str, policy: EvidenceFilePolicy, cap: int) -> str:
    child = _open_checked_file(fd, name, policy)
    try:
        before = os.fstat(child)
        digest = hashlib.sha256()
        total = 0
        while total <= cap:
            chunk = os.read(child, min(64 * 1024, cap + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(child)
        if total > cap:
            raise JobicyEvidenceError("terms_page_digest_invalid")
        if (
            before.st_ino != after.st_ino
            or before.st_dev != after.st_dev
            or before.st_size != after.st_size
        ):
            raise JobicyEvidenceError("terms_page_digest_invalid")
        return digest.hexdigest()
    finally:
        os.close(child)


def _read_bounded(fd: int, cap: int) -> bytes:
    data = b""
    while len(data) <= cap:
        chunk = os.read(fd, min(64 * 1024, cap + 1 - len(data)))
        if not chunk:
            return data
        data += chunk
    raise JobicyEvidenceError("terms_manifest_invalid")


def _open_checked_dir(path: Path, policy: EvidenceFilePolicy, *, root_fd: int | None) -> int:
    del root_fd
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        _check_stat(os.fstat(descriptor), policy, directory=True)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_checked_file(fd: int, name: str, policy: EvidenceFilePolicy) -> int:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
    try:
        _check_stat(os.fstat(descriptor), policy, directory=False)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _check_stat(metadata: os.stat_result, policy: EvidenceFilePolicy, *, directory: bool) -> None:
    if directory and not stat.S_ISDIR(metadata.st_mode):
        raise JobicyEvidenceError("terms_bundle_insecure")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise JobicyEvidenceError("terms_page_missing")
    if metadata.st_uid != policy.owner_uid or (
        policy.group_gid is not None and metadata.st_gid != policy.group_gid
    ):
        raise JobicyEvidenceError("terms_bundle_insecure")
    expected = policy.directory_mode if directory else policy.file_mode
    if stat.S_IMODE(metadata.st_mode) != expected or (
        not directory and metadata.st_nlink != 1
    ):
        raise JobicyEvidenceError("terms_bundle_insecure")


def _parse_zulu(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise JobicyEvidenceError("terms_manifest_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise JobicyEvidenceError("terms_manifest_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise JobicyEvidenceError("terms_manifest_invalid")
    return parsed.astimezone(UTC)


def _role_radar_gid() -> int:
    try:
        return grp.getgrnam("role-radar").gr_gid
    except KeyError as exc:
        raise JobicyEvidenceError("terms_bundle_insecure") from exc


read_jobicy_terms_evidence = load_jobicy_terms_evidence
