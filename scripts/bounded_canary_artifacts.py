"""Descriptor-bound protected artifact creation and writes.

This module has no dependency on the backup orchestrator. Callers supply the
parent/root validation and ownership operations that define their trust policy.
"""
from __future__ import annotations

import os
import stat
from collections.abc import Callable


class ArtifactError(Exception):
    """A fixed failure code for a protected artifact operation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _identity(info) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def verify_file(fd: int, directory_fd: int, name: str, identity: tuple[int, ...], *,
                uid: int, gid: int, mode: int,
                require_owner: Callable[[object, int, int], None],
                validate_parent: Callable[[], None] = lambda: None) -> None:
    """Verify the held file and its named entry against the protected contract."""
    validate_parent()
    opened = os.fstat(fd)
    named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    try:
        require_owner(opened, uid, gid)
        require_owner(named, uid, gid)
    except ArtifactError:
        raise
    except Exception:
        raise ArtifactError("artifact_metadata_invalid") from None
    valid = (stat.S_ISREG(opened.st_mode) and stat.S_ISREG(named.st_mode)
             and stat.S_IMODE(opened.st_mode) == mode
             and stat.S_IMODE(named.st_mode) == mode
             and opened.st_nlink == 1 and named.st_nlink == 1
             and (opened.st_dev, opened.st_ino) == identity[:2]
             and (named.st_dev, named.st_ino) == identity[:2]
             and _identity(opened) == _identity(named))
    if not valid:
        raise ArtifactError("artifact_metadata_invalid")


def create_empty_at(
    directory_fd: int, name: str, *, uid: int, gid: int, mode: int,
    chown: Callable[[int, int, int], None],
    require_owner: Callable[[object, int, int], None],
    validate_parent: Callable[[], None] = lambda: None,
) -> tuple[int, tuple[int, ...]]:
    """Exclusively create and sync an empty regular file with verified metadata."""
    validate_parent()
    flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
             | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(name, flags, mode, dir_fd=directory_fd)
    except FileExistsError:
        raise ArtifactError("artifact_collision") from None
    except Exception:
        raise ArtifactError("artifact_write_failed") from None
    try:
        created = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(created.st_mode) or _identity(created) != _identity(named)):
            raise ArtifactError("artifact_changed")
        try:
            chown(fd, uid, gid)
            os.fchmod(fd, mode)
        except Exception:
            raise ArtifactError("artifact_write_failed") from None
        initial = os.fstat(fd)
        identity = (initial.st_dev, initial.st_ino)
        verify_file(fd, directory_fd, name, _identity(initial), uid=uid, gid=gid, mode=mode,
                    require_owner=require_owner, validate_parent=validate_parent)
        os.fsync(fd)
        return fd, identity
    except Exception:
        os.close(fd)
        raise


def write_new_at(directory_fd: int, name: str, data: bytes, *, uid: int, gid: int,
                 mode: int, chown: Callable[[int, int, int], None],
                 require_owner: Callable[[object, int, int], None],
                 validate_parent: Callable[[], None] = lambda: None) -> tuple[int, ...]:
    """Create, revalidate immediately before bytes, write completely, and sync."""
    fd, identity = create_empty_at(
        directory_fd, name, uid=uid, gid=gid, mode=mode, chown=chown,
        require_owner=require_owner, validate_parent=validate_parent,
    )
    try:
        # This is deliberately adjacent to the first write: creation-time mode
        # and link checks alone do not protect against metadata drift.
        verify_file(fd, directory_fd, name, identity, uid=uid, gid=gid, mode=mode,
                    require_owner=require_owner, validate_parent=validate_parent)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ArtifactError("artifact_write_failed")
            view = view[written:]
        os.fsync(fd)
        verify_file(fd, directory_fd, name, identity, uid=uid, gid=gid, mode=mode,
                    require_owner=require_owner, validate_parent=validate_parent)
        return identity
    except ArtifactError:
        raise
    except Exception:
        raise ArtifactError("artifact_write_failed") from None
    finally:
        os.close(fd)
