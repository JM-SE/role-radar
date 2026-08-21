"""Filesystem-only atomic store for the F10.1C v2 six-file bundle."""

from __future__ import annotations

import fcntl
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from role_radar.evaluation.snapshot_store import canonical_line, sha256_bytes

DATASET_ID = re.compile(r"^[0-9a-f]{64}$")
V2_FILES = (
    "corpus.jsonl",
    "provenance.jsonl",
    "pilot-label-view.jsonl",
    "holdout-label-view.jsonl",
    "internal-manifest.json",
    "checksums.sha256",
)


def _safe_root(root: Path) -> None:
    if not root.is_absolute() or root == Path(root.anchor):
        raise ValueError("snapshot_root_invalid")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("snapshot_symlink_rejected")
        if not current.exists():
            current.mkdir(mode=0o700)
        if not current.is_dir():
            raise ValueError("snapshot_root_not_directory")
    os.chmod(root, 0o700)


def _cleanup(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    for item in path.iterdir():
        if item.is_symlink() or item.is_file():
            item.unlink()
        elif item.is_dir():
            _cleanup(item)
    path.rmdir()


class V2BundleStore:
    FILES = V2_FILES

    def __init__(self, root: Path) -> None:
        self.root = root
        _safe_root(root)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        lock = os.open(self.root / ".publish.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.chmod(self.root / ".publish.lock", 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)

    def publish(
        self,
        *,
        dataset_id: str,
        file_payloads: Mapping[str, bytes],
        internal: Mapping[str, Any],
    ) -> Path:
        if DATASET_ID.fullmatch(dataset_id) is None:
            raise ValueError("dataset_id_invalid")
        expected = set(V2_FILES) - {"internal-manifest.json", "checksums.sha256"}
        if set(file_payloads) != expected:
            raise ValueError("v2_files_invalid")
        counts = internal.get("counts")
        if counts != {"corpus": 177, "pilot": 50, "holdout": 127}:
            raise ValueError("v2_cardinality_invalid")
        payloads = dict(file_payloads)
        payloads["internal-manifest.json"] = canonical_line(dict(internal))
        payloads["checksums.sha256"] = "".join(
            f"{sha256_bytes(payloads[name])}  {name}\n"
            for name in V2_FILES
            if name != "checksums.sha256"
        ).encode("ascii")
        with self._lock():
            target = self.root / dataset_id
            if target.exists() or target.is_symlink():
                if self.verify(dataset_id) and all(
                    (target / name).read_bytes() == value for name, value in payloads.items()
                ):
                    return target
                raise FileExistsError("dataset_id_conflict")
            staging = Path(tempfile.mkdtemp(prefix=f".{dataset_id}.", dir=self.root))
            os.chmod(staging, 0o700)
            try:
                for name, value in payloads.items():
                    path = staging / name
                    path.write_bytes(value)
                    os.chmod(path, 0o600)
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
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
                _cleanup(staging)

    def verify(self, dataset_id: str) -> bool:
        if DATASET_ID.fullmatch(dataset_id) is None:
            return False
        target = self.root / dataset_id
        try:
            children = tuple(target.iterdir())
            if (
                target.is_symlink()
                or not target.is_dir()
                or {item.name for item in children} != set(V2_FILES)
            ):
                return False
            if stat.S_IMODE(target.stat().st_mode) != 0o700 or any(
                item.is_symlink() or stat.S_IMODE(item.stat().st_mode) != 0o600 for item in children
            ):
                return False
            lines = {
                "corpus.jsonl": 177,
                "provenance.jsonl": 177,
                "pilot-label-view.jsonl": 50,
                "holdout-label-view.jsonl": 127,
            }
            if any(
                sum(1 for _ in (target / name).open("rb")) != count
                for name, count in lines.items()
            ):
                return False
            entries = (target / "checksums.sha256").read_text(encoding="ascii").splitlines()
            if len(entries) != 5:
                return False
            seen: set[str] = set()
            for entry in entries:
                digest, separator, name = entry.partition("  ")
                if (
                    separator != "  "
                    or name not in set(V2_FILES) - {"checksums.sha256"}
                    or name in seen
                ):
                    return False
                if not re.fullmatch(r"[0-9a-f]{64}", digest) or sha256_bytes(
                    (target / name).read_bytes()
                ) != digest:
                    return False
                seen.add(name)
            return seen == set(V2_FILES) - {"checksums.sha256"}
        except (OSError, UnicodeError, ValueError):
            return False


BundleStoreV2 = V2BundleStore

__all__ = ["V2_FILES", "BundleStoreV2", "V2BundleStore"]
