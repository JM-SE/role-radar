"""Small, filesystem-only primitives for private content-addressed snapshots.

This module deliberately knows nothing about acquisition or evaluation.  The
older F10.1 implementation imports these primitives through its compatibility
module, while newer evaluation bundles can use the same atomic store.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DATASET_ID = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT_FILES = (
    "dataset.jsonl",
    "provenance.jsonl",
    "label-view.jsonl",
    "internal-manifest.json",
    "checksums.sha256",
)


def _json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: item.isoformat().replace("+00:00", "Z"),
    ).encode("utf-8")


def canonical_json_bytes(value: Any) -> bytes:
    """Return the strict, one-line-independent JSON representation."""

    return _json(value)


def canonical_line(value: Any) -> bytes:
    return _json(value) + b"\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_directory(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("snapshot_root_must_be_absolute")
    if path == Path(path.anchor):
        raise ValueError("snapshot_root_too_broad")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("snapshot_symlink_rejected")
        if not current.exists():
            current.mkdir(mode=0o700)
        if not current.is_dir():
            raise ValueError("snapshot_root_not_directory")
    if path.is_symlink():
        raise ValueError("snapshot_symlink_rejected")
    os.chmod(path, 0o700)
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError("snapshot_directory_mode")


def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def _remove_staging(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    for child in path.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            _remove_staging(child)
    path.rmdir()


class SnapshotStore:
    """Atomic private bundle store; ``root`` is injectable for offline tests."""

    FILES = SNAPSHOT_FILES

    def __init__(self, root: Path) -> None:
        self.root = root
        _safe_directory(root)

    @contextmanager
    def _publish_lock(self) -> Iterator[None]:
        lock_path = self.root / ".publish.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.chmod(lock_path, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def publish(
        self,
        *,
        dataset_id: str,
        dataset_lines: tuple[bytes, ...],
        provenance_lines: tuple[bytes, ...],
        label_lines: tuple[bytes, ...],
        internal: Mapping[str, Any],
    ) -> Path:
        if DATASET_ID.fullmatch(dataset_id) is None:
            raise ValueError("snapshot_dataset_id_invalid")
        if not (len(dataset_lines) == len(provenance_lines) == len(label_lines) == 50):
            raise ValueError("snapshot_requires_exactly_50_records")
        content: dict[str, bytes] = {
            "dataset.jsonl": b"".join(dataset_lines),
            "provenance.jsonl": b"".join(provenance_lines),
            "label-view.jsonl": b"".join(label_lines),
            "internal-manifest.json": canonical_line(dict(internal)),
        }
        content["checksums.sha256"] = "".join(
            f"{sha256_bytes(payload)}  {name}\n" for name, payload in content.items()
        ).encode("ascii")

        with self._publish_lock():
            target = self.root / dataset_id
            if target.exists() or target.is_symlink():
                if self.verify(dataset_id) and all(
                    (target / name).read_bytes() == payload for name, payload in content.items()
                ):
                    return target
                raise FileExistsError("snapshot_id_conflict")
            staging = Path(tempfile.mkdtemp(prefix=f".{dataset_id}.", dir=self.root))
            os.chmod(staging, 0o700)
            try:
                for name, payload in content.items():
                    target_file = staging / name
                    target_file.write_bytes(payload)
                    os.chmod(target_file, 0o600)
                for name in self.FILES:
                    _fsync_file(staging / name)
                directory_fd = os.open(staging, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                os.rename(staging, target)
                directory_fd = os.open(self.root, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                return target
            finally:
                _remove_staging(staging)

    def verify(self, dataset_id: str) -> bool:
        if DATASET_ID.fullmatch(dataset_id) is None:
            return False
        target = self.root / dataset_id
        try:
            if not target.is_dir() or target.is_symlink():
                return False
            children = tuple(target.iterdir())
            if any(item.is_symlink() for item in children):
                return False
            if {item.name for item in children} != set(self.FILES):
                return False
            if stat.S_IMODE(target.stat().st_mode) != 0o700:
                return False
            if any(stat.S_IMODE(item.stat().st_mode) != 0o600 for item in children):
                return False
            for name in ("dataset.jsonl", "provenance.jsonl", "label-view.jsonl"):
                with (target / name).open("rb") as stream:
                    if sum(1 for _ in stream) != 50:
                        return False
            entries = (target / "checksums.sha256").read_text(encoding="ascii").splitlines()
            if len(entries) != 4:
                return False
            seen: set[str] = set()
            for entry in entries:
                digest, separator, name = entry.partition("  ")
                if separator != "  " or name not in self.FILES or name == "checksums.sha256":
                    return False
                if not re.fullmatch(r"[0-9a-f]{64}", digest) or name in seen:
                    return False
                seen.add(name)
                if sha256_bytes((target / name).read_bytes()) != digest:
                    return False
            return seen == set(self.FILES) - {"checksums.sha256"}
        except (OSError, UnicodeError, ValueError):
            return False


__all__ = [
    "DATASET_ID",
    "SNAPSHOT_FILES",
    "SnapshotStore",
    "canonical_json_bytes",
    "canonical_line",
    "sha256_bytes",
]
