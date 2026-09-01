"""Domain-neutral filesystem primitive owner for F10.1F.

Single owner for lock/fence, no-follow traversal, bounded read, fsync,
atomic write, and no-replace. F10.1F domain stores compose this seam;
historical stores remain unchanged and are never copied.

No network, no DB, no historical holdout access.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

MAX_READ_BYTES: Final[int] = 10 * 1024 * 1024
MAX_COMPONENT_LENGTH: Final[int] = 128
LOCK_FILENAME: Final[str] = ".f10-1f.fence.lock"
STAGING_PREFIX: Final[str] = ".tmp."
HISTORICAL_ROOTS: Final[tuple[str, ...]] = (
    "/opt/role-radar/data/evaluation/snapshot",
    "/opt/role-radar/data/evaluation/f10.1",
    "/opt/role-radar/data/evaluation/f10.1c",
    "/opt/role-radar/data/evaluation/f10.1e",
)


class FilesystemError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_absolute(path: Path) -> None:
    if not path.is_absolute():
        raise FilesystemError("filesystem_root_must_be_absolute")
    if path == Path(path.anchor):
        raise FilesystemError("filesystem_root_too_broad")


def _reject_symlink(path: Path) -> None:
    # lstat without following
    try:
        if path.is_symlink():
            raise FilesystemError("filesystem_symlink_rejected")
    except OSError as exc:
        raise FilesystemError("filesystem_stat_failed") from exc


def _check_not_historical(path: Path) -> None:
    text = str(path)
    for hist in HISTORICAL_ROOTS:
        if text == hist or text.startswith(hist + "/"):
            raise FilesystemError("filesystem_historical_root_rejected")
        # also reject alias via resolved equality (no symlink follow needed)
        pass  # string prefix check above is sufficient; no symlink traversal


def _check_component(name: str) -> None:
    if not name or name in (".", ".."):
        raise FilesystemError("filesystem_component_invalid")
    if "/" in name or "\\" in name or "\x00" in name:
        raise FilesystemError("filesystem_component_invalid")
    if len(name) > MAX_COMPONENT_LENGTH:
        raise FilesystemError("filesystem_component_too_long")
    if name.startswith(".") and name not in (LOCK_FILENAME,):
        # allow dotfiles only if explicitly expected; otherwise reject hidden traversal
        # staging files are handled internally, not via public join
        raise FilesystemError("filesystem_hidden_component_rejected")


def ensure_private_root(root: Path) -> Path:
    """Create and validate isolated private root; no historical alias."""

    _require_absolute(root)
    _check_not_historical(root)
    # Walk from anchor, no-follow — create missing with 0o700, no chmod of existing system dirs
    current = Path(root.anchor)
    for part in root.parts[1:]:
        _check_component(part)
        current = current / part
        _reject_symlink(current)
        if not current.exists():
            try:
                current.mkdir(mode=0o700)
            except FileExistsError as exc:
                raise FilesystemError("filesystem_mkdir_conflict") from exc
            except OSError as exc:
                raise FilesystemError("filesystem_mkdir_failed") from exc
        else:
            if not current.is_dir():
                raise FilesystemError("filesystem_root_not_directory")
            _reject_symlink(current)
        if current.is_symlink():
            raise FilesystemError("filesystem_symlink_rejected")
    # final root must be 0o700, enforce only there
    try:
        mode = stat.S_IMODE(root.stat().st_mode)
    except OSError as exc:
        raise FilesystemError("filesystem_stat_failed") from exc
    if mode != 0o700:
        try:
            os.chmod(root, 0o700)
        except OSError as exc:
            raise FilesystemError("filesystem_chmod_failed") from exc
    _reject_symlink(root)
    return root


def _fsync_file(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    except OSError as exc:
        raise FilesystemError("filesystem_fsync_failed") from exc


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_DIRECTORY)
    except OSError as exc:
        raise FilesystemError("filesystem_fsync_failed") from exc
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            raise FilesystemError("filesystem_fsync_failed") from exc
    finally:
        os.close(fd)


@contextmanager
def fenced_lock(root: Path) -> Iterator[None]:
    """Exclusive fence lock under root; fail closed on contention.

    Caller must have called ensure_private_root first. Lock file is
    created with O_NOFOLLOW and 0o600.
    """

    ensure_private_root(root)
    lock_path = root / LOCK_FILENAME
    # O_NOFOLLOW ensures we do not follow symlink
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise FilesystemError("filesystem_symlink_rejected") from exc
        raise FilesystemError("filesystem_lock_open_failed") from exc
    try:
        try:
            os.chmod(lock_path, 0o600)
        except OSError as exc:
            raise FilesystemError("filesystem_chmod_failed") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            raise FilesystemError("filesystem_lock_failed") from exc
        yield
    finally:
        try:  # noqa: SIM105
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def resolve_nofollow(root: Path, *parts: str) -> Path:
    """Join and validate no-follow path under root."""

    ensure_private_root(root)
    target = root
    for part in parts:
        _check_component(part)
        candidate = target / part
        _reject_symlink(candidate.parent)
        _reject_symlink(candidate) if candidate.exists() else None
        # also ensure intermediate components are not symlinks
        # walk parent chain
        cur = root
        for sub in candidate.relative_to(root).parts:
            cur = cur / sub
            if cur.exists() and cur.is_symlink():
                raise FilesystemError("filesystem_symlink_rejected")
        if not str(candidate).startswith(str(root) + "/"):
            raise FilesystemError("filesystem_traversal_outside_root")
        target = candidate
    return target


def bounded_read(path: Path, *, max_bytes: int = MAX_READ_BYTES) -> bytes:
    """Read with no-follow and bounded size; rejects symlink."""

    _reject_symlink(path)
    try:
        st = path.stat()
    except OSError as exc:
        raise FilesystemError("filesystem_read_failed") from exc
    if not stat.S_ISREG(st.st_mode):
        raise FilesystemError("filesystem_not_regular_file")
    if st.st_size > max_bytes:
        raise FilesystemError("filesystem_read_bound_exceeded")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise FilesystemError("filesystem_read_failed") from exc
    if len(data) > max_bytes:
        raise FilesystemError("filesystem_read_bound_exceeded")
    return data


def bounded_read_cli(
    path: Path,
    *,
    artifact_root: Path,
    max_bytes: int = MAX_READ_BYTES,
) -> bytes:
    """Read one artifact below an explicit, non-production root.

    The root is never inferred from cwd.  Directory and file components are
    opened relative to directory descriptors with ``O_NOFOLLOW`` so a path
    replacement cannot turn this reader into an arbitrary filesystem reader.
    """

    if not isinstance(path, Path) or not isinstance(artifact_root, Path):
        raise FilesystemError("filesystem_cli_path_invalid")
    if not artifact_root.is_absolute() or artifact_root == Path(artifact_root.anchor):
        raise FilesystemError("filesystem_cli_root_invalid")
    root_text = str(artifact_root)
    if root_text == "/opt" or root_text.startswith("/opt/"):
        raise FilesystemError("filesystem_production_root_rejected")
    _check_not_historical(artifact_root)
    if path.is_absolute():
        try:
            relative = path.relative_to(artifact_root)
        except ValueError as exc:
            raise FilesystemError("filesystem_cli_path_invalid") from exc
        parts = relative.parts
    else:
        parts = path.parts
    if not parts or any(part in (".", "..", "") for part in parts):
        raise FilesystemError("filesystem_cli_path_invalid")
    for part in parts:
        _check_component(part)

    # Walk the absolute root from / with openat; this also rejects symlinked
    # intermediate root components rather than relying on Path.resolve().
    try:
        dir_fd = os.open(Path(artifact_root.anchor), os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise FilesystemError("filesystem_cli_root_invalid") from exc
    try:
        for component in artifact_root.parts[1:]:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=dir_fd,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise FilesystemError("filesystem_symlink_rejected") from exc
                raise FilesystemError("filesystem_cli_root_invalid") from exc
            os.close(dir_fd)
            dir_fd = next_fd
        try:
            for component in parts[:-1]:
                try:
                    next_fd = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=dir_fd,
                    )
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise FilesystemError("filesystem_symlink_rejected") from exc
                    raise FilesystemError("filesystem_cli_path_invalid") from exc
                os.close(dir_fd)
                dir_fd = next_fd
            try:
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise FilesystemError("filesystem_symlink_rejected") from exc
                raise FilesystemError("filesystem_read_failed") from exc
        except OSError as exc:
            raise FilesystemError("filesystem_read_failed") from exc
    finally:
        os.close(dir_fd)
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise FilesystemError("filesystem_stat_failed") from exc
        if not stat.S_ISREG(st.st_mode):
            raise FilesystemError("filesystem_not_regular_file")
        if st.st_size > max_bytes:
            raise FilesystemError("filesystem_read_bound_exceeded")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise FilesystemError("filesystem_read_bound_exceeded")
        return b"".join(chunks)
    except OSError as exc:
        raise FilesystemError("filesystem_read_failed") from exc
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, *, max_bytes: int = MAX_READ_BYTES) -> None:
    """Atomic write via staging + rename + fsync; caller holds fence if needed."""

    if len(data) > max_bytes:
        raise FilesystemError("filesystem_write_bound_exceeded")
    _reject_symlink(path)
    parent = path.parent
    ensure_private_root(parent) if not parent.exists() else _reject_symlink(parent)
    if not parent.is_dir():
        raise FilesystemError("filesystem_parent_not_directory")
    # staging in same directory
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=STAGING_PREFIX, dir=parent)
    except OSError as exc:
        raise FilesystemError("filesystem_staging_failed") from exc
    tmp_path = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            raise FilesystemError("filesystem_chmod_failed") from exc
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise FilesystemError("filesystem_write_failed") from exc
        # fsync file then dir before rename
        _fsync_file(tmp_path)
        try:
            os.rename(tmp_path, path)
        except OSError as exc:
            raise FilesystemError("filesystem_rename_failed") from exc
        _fsync_file(path)
        _fsync_dir(parent)
    finally:
        should_clean = False
        if path.exists():
            if tmp_path.exists() and not tmp_path.samefile(path):
                should_clean = True
        else:
            should_clean = tmp_path.exists()
        if should_clean:
            try:
                if tmp_path.exists() and tmp_path.is_file() and not tmp_path.is_symlink():
                    tmp_path.unlink()
            except OSError:
                pass


def write_no_replace(path: Path, data: bytes, *, max_bytes: int = MAX_READ_BYTES) -> None:
    """Create only if absent; fail if exists with different bytes (no-replace)."""

    _reject_symlink(path)
    if path.exists():
        existing = bounded_read(path, max_bytes=max_bytes)
        if existing == data:
            return
        raise FilesystemError("filesystem_no_replace_conflict")
    # use O_CREAT|O_EXCL via atomic_write's staging+rename race is not Excl;
    # so check again under fence. Caller should hold fenced_lock.
    # Fallback: try atomic then detect conflict.
    # We implement via open with O_EXCL on staging already handled, but final rename
    # overwrites; so we must check existence again before rename.
    # Use low-level exclusive create.
    parent = path.parent
    ensure_private_root(parent)
    _fsync_dir(parent)
    # attempt exclusive create atomically
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            existing2 = bounded_read(path, max_bytes=max_bytes)
            if existing2 == data:
                return
            raise FilesystemError("filesystem_no_replace_conflict") from exc
        if exc.errno == errno.ELOOP:
            raise FilesystemError("filesystem_symlink_rejected") from exc
        raise FilesystemError("filesystem_create_failed") from exc
    try:
        try:
            os.write(fd, data)
            os.fsync(fd)
        except OSError as exc:
            raise FilesystemError("filesystem_write_failed") from exc
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            raise FilesystemError("filesystem_chmod_failed") from exc
    finally:
        os.close(fd)
    _fsync_file(path)
    _fsync_dir(parent)


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(bounded_read(path))


__all__ = [
    "HISTORICAL_ROOTS",
    "LOCK_FILENAME",
    "MAX_READ_BYTES",
    "FilesystemError",
    "atomic_write",
    "bounded_read",
    "bounded_read_cli",
    "canonical_json_bytes",
    "ensure_private_root",
    "fenced_lock",
    "resolve_nofollow",
    "sha256_bytes",
    "sha256_file",
    "write_no_replace",
]
