"""Domain-neutral private filesystem primitives for F10.2."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path


class FilesystemError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def open_directory_chain(path: Path) -> int:
    if not path.is_absolute() or path == Path(path.anchor):
        raise FilesystemError("root_invalid")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    current = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def open_private_directory(path: Path) -> int:
    fd = open_directory_chain(path)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
        ):
            raise FilesystemError("directory_not_private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def fsync_directory(path: Path) -> None:
    fd = open_directory_chain(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_private_root(root: Path, *, create: bool = True) -> None:
    if not root.is_absolute() or root == Path(root.anchor):
        raise FilesystemError("root_invalid")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    current = os.open(root.anchor, flags)
    try:
        for part in root.parts[1:]:
            try:
                next_fd = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise FilesystemError("root_missing") from None
                os.mkdir(part, mode=0o700, dir_fd=current)
                next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        metadata = os.fstat(current)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise FilesystemError("root_not_private")
    except FilesystemError:
        raise
    except OSError as exc:
        raise FilesystemError("root_invalid") from exc
    finally:
        os.close(current)


def verify_private_file(path: Path) -> None:
    parent_fd = open_directory_chain(path.parent)
    try:
        fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
            ):
                raise FilesystemError("file_not_private")
        finally:
            os.close(fd)
    except FilesystemError:
        raise
    except OSError as exc:
        raise FilesystemError("file_not_private") from exc
    finally:
        os.close(parent_fd)


def read_bounded(path: Path, limit: int) -> bytes:
    parent_fd = open_directory_chain(path.parent)
    try:
        fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
            ):
                raise FilesystemError("file_not_private")
            chunks: list[bytes] = []
            total = 0
            while total <= limit:
                chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)
    except FilesystemError:
        raise
    except OSError as exc:
        raise FilesystemError("file_read_failed") from exc
    finally:
        os.close(parent_fd)
    if len(data) > limit:
        raise FilesystemError("file_too_large")
    return data


def read_bounded_fd(directory_fd: int, name: str, limit: int) -> bytes:
    fd = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise FilesystemError("file_not_private")
        chunks: list[bytes] = []
        total = 0
        while total <= limit:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise FilesystemError("file_too_large")
        return data
    finally:
        os.close(fd)


@contextmanager
def locked(lock_path: Path, *, create: bool = True) -> Iterator[None]:
    ensure_private_root(lock_path.parent, create=create)
    parent_fd = open_private_directory(lock_path.parent)
    fd: int | None = None
    try:
        if create:
            fd = os.open(
                lock_path.name,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_fd,
            )
        else:
            fd = os.open(
                lock_path.name,
                os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
    except FileNotFoundError as exc:
        os.close(parent_fd)
        raise FilesystemError("lock_missing") from exc
    except OSError as exc:
        os.close(parent_fd)
        raise FilesystemError("lock_failed") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
        ):
            raise FilesystemError("lock_invalid")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    except FilesystemError:
        raise
    except OSError as exc:
        raise FilesystemError("lock_failed") from exc
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            os.close(parent_fd)


def atomic_write(path: Path, payload: bytes) -> None:
    ensure_private_root(path.parent)
    parent_fd = open_private_directory(path.parent)
    name = f".{path.name}.{secrets.token_hex(12)}"
    fd: int | None = None
    try:
        for _attempt in range(10):
            try:
                fd = os.open(
                    name,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_WRONLY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                break
            except FileExistsError:
                name = f".{path.name}.{secrets.token_hex(12)}"
        if fd is None:
            raise FilesystemError("temp_create_failed")
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if fd is not None:
            os.close(fd)
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=parent_fd)
        os.close(parent_fd)


def publish_no_replace(staging: Path, target: Path) -> None:
    if staging.parent != target.parent or staging.name == target.name:
        raise FilesystemError("publish_path_invalid")
    parent_fd = open_private_directory(target.parent)
    try:
        staging_fd = os.open(
            staging.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            metadata = os.fstat(staging_fd)
            if (
                stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()
            ):
                raise FilesystemError("staging_not_private")
        finally:
            os.close(staging_fd)
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise FilesystemError("no_replace_unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_fd,
            os.fsencode(staging.name),
            parent_fd,
            os.fsencode(target.name),
            1,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise FilesystemError("publish_conflict")
            raise OSError(error, os.strerror(error))
        os.fsync(parent_fd)
    except OSError as exc:
        raise FilesystemError("publish_failed") from exc
    finally:
        os.close(parent_fd)


__all__ = [
    "FilesystemError", "atomic_write", "ensure_private_root", "fsync_directory", "locked",
    "open_directory_chain", "open_private_directory", "publish_no_replace", "read_bounded",
    "read_bounded_fd", "verify_private_file",
]
