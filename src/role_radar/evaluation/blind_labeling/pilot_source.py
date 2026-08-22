"""Fail-closed adapter for exactly one pinned pilot JSONL file."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from role_radar.evaluation.blind_labeling.contracts import PilotSnapshot
from role_radar.evaluation.blind_labeling.policy import (
    DATASET_ID,
    MAX_PILOT_FILE_BYTES,
    PILOT_COUNT,
    PILOT_FILE_SHA256,
    PILOT_FILENAME,
    PILOT_SHA256,
    SOURCE_ROOT,
)
from role_radar.evaluation.blind_labeling.validation import ValidationError, parse_pilot_line


class PilotSourceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PilotSource:
    """Reads only the exact pilot file; ``root`` is injectable for tests."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        dataset_id: str = DATASET_ID,
        pilot_sha256: str = PILOT_SHA256,
        pilot_file_sha256: str = PILOT_FILE_SHA256,
    ) -> None:
        self.root = root or Path(SOURCE_ROOT)
        self.dataset_id = dataset_id
        self.pilot_sha256 = pilot_sha256
        self.pilot_file_sha256 = pilot_file_sha256

    @property
    def path(self) -> Path:
        return self.root / self.dataset_id / PILOT_FILENAME

    def load(self) -> PilotSnapshot:
        path = self.path
        try:
            dataset_dir = self.root / self.dataset_id
            if dataset_dir.is_symlink() or not dataset_dir.is_dir():
                raise PilotSourceError("pilot_directory_invalid")
            if stat.S_IMODE(dataset_dir.stat().st_mode) != 0o700:
                raise PilotSourceError("pilot_directory_mode")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(path, flags)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
                    raise PilotSourceError("pilot_file_mode")
                if before.st_uid != os.geteuid():
                    raise PilotSourceError("pilot_file_owner")
                chunks: list[bytes] = []
                total = 0
                while total <= MAX_PILOT_FILE_BYTES:
                    chunk = os.read(fd, min(1024 * 1024, MAX_PILOT_FILE_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                data = b"".join(chunks)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            if before.st_ino != after.st_ino or before.st_size != after.st_size:
                raise PilotSourceError("pilot_file_changed")
        except PilotSourceError:
            raise
        except (OSError, ValueError) as exc:
            raise PilotSourceError("pilot_file_unavailable") from exc
        if len(data) > MAX_PILOT_FILE_BYTES:
            raise PilotSourceError("pilot_file_too_large")
        actual_file_sha = hashlib.sha256(data).hexdigest()
        if actual_file_sha != self.pilot_file_sha256:
            raise PilotSourceError("pilot_file_hash_mismatch")
        lines = data.splitlines(keepends=True)
        if len(lines) != PILOT_COUNT or any(not line.strip() for line in lines):
            raise PilotSourceError("pilot_cardinality_invalid")
        items = []
        try:
            for line in lines:
                items.append(parse_pilot_line(line))
        except ValidationError as exc:
            raise PilotSourceError(exc.code) from exc
        if len({item.opaque_id for item in items}) != PILOT_COUNT:
            raise PilotSourceError("pilot_duplicate_id")
        return PilotSnapshot(tuple(items), self.dataset_id, self.pilot_sha256, actual_file_sha)


__all__ = ["PilotSource", "PilotSourceError"]
