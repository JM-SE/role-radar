"""Domain-neutral private filesystem primitives for F10.2."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class FilesystemError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def ensure_private_root(root: Path, *, create: bool = True) -> None:
    if not root.is_absolute() or root == Path(root.anchor):
        raise FilesystemError("root_invalid")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current /= part
        if current.is_symlink():
            raise FilesystemError("root_symlink")
        if not current.exists():
            if not create:
                raise FilesystemError("root_missing")
            current.mkdir(mode=0o700)
        if not current.is_dir():
            raise FilesystemError("root_not_directory")
    os.chmod(root, 0o700)


def verify_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise FilesystemError("file_not_private")


def read_bounded(path: Path, limit: int) -> bytes:
    verify_private_file(path)
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as exc:
        raise FilesystemError("file_read_failed") from exc
    if len(data) > limit:
        raise FilesystemError("file_too_large")
    return data


@contextmanager
def locked(lock_path: Path, *, create: bool = True) -> Iterator[None]:
    if create:
        lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    else:
        if not lock_path.exists():
            raise FilesystemError("lock_missing")
        fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        os.chmod(lock_path, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    except OSError as exc:
        raise FilesystemError("lock_failed") from exc
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temp.exists() or temp.is_symlink():
            temp.unlink()


def publish_no_replace(staging: Path, target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise FilesystemError("publish_conflict")
    try:
        os.rename(staging, target)
        directory = os.open(target.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise FilesystemError("publish_failed") from exc


__all__ = [
    "FilesystemError", "atomic_write", "ensure_private_root", "locked", "publish_no_replace",
    "read_bounded", "verify_private_file",
]
