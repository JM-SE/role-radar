"""Fail-closed advisory execution fencing for cooperating local processes.

The caller supplies an existing absolute lock path, expected file metadata, and
an expected permission mode.  The primitive never creates or changes that
path.  It opens every directory component with ``O_NOFOLLOW`` and retains those
descriptors plus the lock descriptor for the whole context.  ``verify`` compares
the retained descriptors to their names, detecting replacement and metadata
drift before a bounded operation.

This is cooperative protection only.  A privileged process can unlink or
replace a pathname, ignore ``flock`` entirely, or mutate an inode between
checks; no pathname-based primitive can provide a temporal guarantee against
that authority.  Callers must treat a failed ``verify`` as a failed/uncertain
operation and stop.
"""

from __future__ import annotations

import fcntl
import os
import stat
import threading
from contextlib import suppress
from types import TracebackType
from typing import Self


class FenceError(RuntimeError):
    """Sanitized, stable error raised for every fence failure."""

    CODE = "execution_fence_unavailable"

    def __init__(self) -> None:
        self.code = self.CODE
        super().__init__(self.CODE)


_FileMetadata = tuple[int, int, int, int, int, int]
_DirectoryMetadata = tuple[int, int, int, int, int]
_MAX_ID = (1 << 32) - 1
_MAX_MODE = 0o7777
_fork_guard = threading.RLock()
_held_fences = {}


def _after_fork_child() -> None:
    # flock belongs to the open-file description shared across fork.  A child
    # must close its duplicate without LOCK_UN, which would unlock the parent.
    for fence in _held_fences.values():
        if fence._fd is not None:
            with suppress(OSError):
                os.close(fence._fd)
        for fd in reversed(fence._directory_fds):
            with suppress(OSError):
                os.close(fd)
        fence._fd = None
        fence._parent_fd = None
        fence._directory_fds = []
        fence._directory_paths = []
        fence._directory_metadata = []
        fence._file_metadata = None
    _held_fences.clear()
    _fork_guard.release()


os.register_at_fork(
    before=_fork_guard.acquire,
    after_in_parent=_fork_guard.release,
    after_in_child=_after_fork_child,
)


def _error() -> FenceError:
    return FenceError()


def _validate_id(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_ID:  # bool is intentionally rejected.
        raise _error()
    return value


def _validate_mode(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_MODE:
        raise _error()
    return value


def _validate_path(path: object) -> str:
    try:
        value = os.fspath(path)
    except (TypeError, ValueError, OSError):
        raise _error() from None
    if (
        not isinstance(value, str)
        or not value
        or value == os.sep
        or "\x00" in value
        or not os.path.isabs(value)
    ):
        raise _error()
    try:
        # Normalize spelling lexically; never resolve or follow symlinks.
        value = os.path.abspath(value)
    except (TypeError, ValueError, OSError):
        raise _error() from None
    return value


def _metadata_from_file(info: os.stat_result) -> _FileMetadata:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
    )


def _metadata_from_directory(info: os.stat_result) -> _DirectoryMetadata:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
    )


def _read_file_metadata(
    fd: int,
    parent_fd: int,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> _FileMetadata:
    """Read the retained file and its anchored name, requiring one inode."""

    try:
        before = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        after = os.fstat(fd)
    except (OSError, ValueError):
        raise _error() from None
    if not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(named.st_mode):
        raise _error()
    fd_metadata = _metadata_from_file(before)
    if fd_metadata != _metadata_from_file(after) or fd_metadata != _metadata_from_file(named):
        raise _error()
    if (
        fd_metadata[2] != expected_uid
        or fd_metadata[3] != expected_gid
        or fd_metadata[4] != expected_mode
        or fd_metadata[5] != 1
    ):
        raise _error()
    return fd_metadata


def _directory_allowed(info: os.stat_result, *, expected_uid: int) -> bool:
    if not stat.S_ISDIR(info.st_mode):
        return False
    # Ancestors may be owned by root or by the configured integrator.  A
    # writable ancestor is accepted only for a root-owned sticky directory
    # (the /tmp policy); all other group/other writes are unsafe.
    mode = stat.S_IMODE(info.st_mode)
    owner_allowed = info.st_uid in {0, expected_uid}
    writable = bool(mode & 0o022)
    sticky_safe = bool(mode & stat.S_ISVTX) and info.st_uid == 0
    return owner_allowed and (not writable or sticky_safe)


def _read_directory_metadata(
    fd: int, name: str | None, parent_fd: int | None, *, expected_uid: int
) -> _DirectoryMetadata:
    try:
        retained = os.fstat(fd)
        if name is None:
            named = retained
        elif parent_fd is None:
            named = os.stat(name, follow_symlinks=False)
        else:
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except (OSError, ValueError):
        raise _error() from None
    if not _directory_allowed(retained, expected_uid=expected_uid):
        raise _error()
    if _metadata_from_directory(retained) != _metadata_from_directory(named):
        raise _error()
    return _metadata_from_directory(retained)


def _best_effort_close(fds: list[int], *, unlock_fd: int | None = None) -> None:
    if unlock_fd is not None:
        with suppress(OSError, ValueError):
            fcntl.flock(unlock_fd, fcntl.LOCK_UN)
        with suppress(OSError, ValueError):
            os.close(unlock_fd)
    for fd in reversed(fds):
        with suppress(OSError, ValueError):
            os.close(fd)


class _ExecutionFence:
    __slots__ = (
        "_directory_fds",
        "_directory_metadata",
        "_directory_paths",
        "_exclusive",
        "_fd",
        "_file_metadata",
        "_file_name",
        "_gid",
        "_mode",
        "_parent_fd",
        "_path",
        "_uid",
    )

    def __init__(
        self, path: str, *, exclusive: bool, uid: int, gid: int, mode: int
    ) -> None:
        self._path = path
        self._uid = uid
        self._gid = gid
        self._mode = mode
        self._exclusive = exclusive
        self._fd: int | None = None
        self._parent_fd: int | None = None
        self._directory_fds: list[int] = []
        self._directory_paths: list[str] = []
        self._directory_metadata: list[_DirectoryMetadata] = []
        self._file_metadata: _FileMetadata | None = None
        self._file_name = os.path.basename(path)

    def _open_anchored_path(
        self,
    ) -> tuple[int, int, list[int], list[str], list[_DirectoryMetadata]]:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        root_fd = os.open(os.sep, flags)
        directory_fds = [root_fd]
        directory_paths = [os.sep]
        try:
            directory_metadata = [
                _read_directory_metadata(root_fd, None, None, expected_uid=self._uid)
            ]
            current_fd = root_fd
            current_path = os.sep
            components = [part for part in self._path.split(os.sep) if part]
            for component in components[:-1]:
                child_fd = os.open(component, flags, dir_fd=current_fd)
                directory_fds.append(child_fd)
                current_path = os.path.join(current_path, component)
                directory_paths.append(current_path)
                directory_metadata.append(
                    _read_directory_metadata(
                        child_fd,
                        component,
                        current_fd,
                        expected_uid=self._uid,
                    )
                )
                current_fd = child_fd
            file_fd = os.open(
                components[-1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current_fd,
            )
            return file_fd, current_fd, directory_fds, directory_paths, directory_metadata
        except BaseException:
            _best_effort_close(directory_fds)
            raise

    def __enter__(self) -> Self:
        with _fork_guard:
            return self._enter_locked()

    def _enter_locked(self) -> Self:
        if self._fd is not None:
            raise _error()
        try:
            fd, parent_fd, directory_fds, directory_paths, directory_metadata = (
                self._open_anchored_path()
            )
        except (AttributeError, OSError, ValueError, FenceError):
            raise _error() from None
        self._fd = fd
        _held_fences[fd] = self
        self._parent_fd = parent_fd
        self._directory_fds = directory_fds
        self._directory_paths = directory_paths
        self._directory_metadata = directory_metadata
        try:
            operation = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            self._file_metadata = _read_file_metadata(
                fd,
                parent_fd,
                self._file_name,
                expected_uid=self._uid,
                expected_gid=self._gid,
                expected_mode=self._mode,
            )
        except Exception:
            _held_fences.pop(fd, None)
            _best_effort_close(directory_fds, unlock_fd=fd)
            self._fd = None
            self._parent_fd = None
            self._directory_fds = []
            self._directory_paths = []
            self._directory_metadata = []
            self._file_metadata = None
            raise _error() from None
        return self

    def verify(self) -> Self:
        """Revalidate retained directories, inode, ownership, and permissions."""

        fd = self._fd
        parent_fd = self._parent_fd
        expected_file = self._file_metadata
        if fd is None or parent_fd is None or expected_file is None:
            raise _error()
        try:
            for directory_fd, directory_path, expected in zip(
                self._directory_fds,
                self._directory_paths,
                self._directory_metadata,
                strict=True,
            ):
                current = _read_directory_metadata(
                    directory_fd,
                    directory_path,
                    None,
                    expected_uid=self._uid,
                )
                if current != expected:
                    raise _error()
            current_file = _read_file_metadata(
                fd,
                parent_fd,
                self._file_name,
                expected_uid=self._uid,
                expected_gid=self._gid,
                expected_mode=self._mode,
            )
        except FenceError:
            raise
        if current_file != expected_file:
            raise _error()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        with _fork_guard:
            return self._exit_locked()

    def _exit_locked(self) -> bool:
        fd = self._fd
        if fd is not None:
            _held_fences.pop(fd, None)
        directory_fds = self._directory_fds
        self._fd = None
        self._parent_fd = None
        self._directory_fds = []
        self._directory_paths = []
        self._file_metadata = None
        if fd is None:
            return False
        failure = False
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except (OSError, ValueError):
            failure = True
        try:
            os.close(fd)
        except (OSError, ValueError):
            failure = True
        for directory_fd in reversed(directory_fds):
            try:
                os.close(directory_fd)
            except (OSError, ValueError):
                failure = True
        if failure:
            raise _error()
        return False


def acquire(
    path: str | os.PathLike[str], *, exclusive: bool, uid: int, gid: int, mode: int
) -> _ExecutionFence:
    """Return a context manager holding a nonblocking shared/exclusive fence.

    ``path`` must already name a regular, singly-linked, non-symlink file with
    exactly ``mode`` permissions.  ``uid`` and ``gid`` are integrator-supplied
    expected metadata, not values read from the path.
    """

    if type(exclusive) is not bool:
        raise _error()
    validated_path = _validate_path(path)
    validated_uid = _validate_id(uid)
    validated_gid = _validate_id(gid)
    validated_mode = _validate_mode(mode)
    return _ExecutionFence(
        validated_path,
        exclusive=exclusive,
        uid=validated_uid,
        gid=validated_gid,
        mode=validated_mode,
    )


__all__ = ["FenceError", "acquire"]
