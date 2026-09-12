"""Descriptor-safe output writer for the recovered synthetic Gate D seam."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

from .post_c_recovery_filesystem import (
    RecoveryFilesystemError,
    list_children,
    pinned_root,
    read_optional_bytes,
    write_no_replace,
)

ARTIFACT_NAMES = frozenset(
    {"journal.json", "checkpoint.json", "evidence.json", "parent-pool.json", "manifest.json"}
)


class RecoveredGateDExecutionFilesystemError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RecoveredGateDExecutionFilesystemWriter:
    """Use an already-created empty 0700 directory without creating or chmodding it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        try:
            with pinned_root(root) as root_fd:
                names = set(list_children(root_fd))
                if names and names != set(ARTIFACT_NAMES):
                    raise RecoveredGateDExecutionFilesystemError("gate_d_execution_output_conflict")
                metadata = os.fstat(root_fd)
                if metadata.st_uid != os.geteuid():
                    raise RecoveredGateDExecutionFilesystemError(
                        "gate_d_execution_output_root_owner_invalid"
                    )
                self.identity = (metadata.st_dev, metadata.st_ino)
        except RecoveredGateDExecutionFilesystemError:
            raise
        except (OSError, RecoveryFilesystemError) as exc:
            raise RecoveredGateDExecutionFilesystemError(
                "gate_d_execution_output_root_invalid"
            ) from exc

    def _check_name(self, name: str) -> None:
        if type(name) is not str or name not in ARTIFACT_NAMES:
            raise RecoveredGateDExecutionFilesystemError("gate_d_execution_artifact_invalid")

    def read(self, name: str) -> bytes | None:
        self._check_name(name)
        try:
            with pinned_root(self.root) as root_fd:
                fcntl.flock(root_fd, fcntl.LOCK_SH)
                try:
                    return read_optional_bytes(
                        root_fd,
                        self.root,
                        self.root / name,
                        expected_identity=self.identity,
                    )
                finally:
                    fcntl.flock(root_fd, fcntl.LOCK_UN)
        except (OSError, RecoveryFilesystemError) as exc:
            raise RecoveredGateDExecutionFilesystemError("gate_d_execution_output_invalid") from exc

    def publish(self, name: str, payload: bytes) -> None:
        self._check_name(name)
        try:
            write_no_replace(
                self.root,
                (name,),
                payload,
                expected_identity=self.identity,
                expected_directory=None,
                allowed_leaves=ARTIFACT_NAMES,
            )
        except (OSError, RecoveryFilesystemError) as exc:
            raise RecoveredGateDExecutionFilesystemError(
                getattr(exc, "code", "gate_d_execution_output_failed")
            ) from exc

    def list_names(self) -> tuple[str, ...]:
        try:
            with pinned_root(self.root) as root_fd:
                return list_children(root_fd)
        except (OSError, RecoveryFilesystemError) as exc:
            raise RecoveredGateDExecutionFilesystemError("gate_d_execution_output_invalid") from exc


__all__ = [
    "ARTIFACT_NAMES",
    "RecoveredGateDExecutionFilesystemError",
    "RecoveredGateDExecutionFilesystemWriter",
]
