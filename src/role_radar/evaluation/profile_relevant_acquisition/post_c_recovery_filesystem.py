"""Descriptor-relative filesystem primitives for recovered Post-C inputs/effects."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from hashlib import sha256
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 256 * 1024
MAX_SEAL_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4096


class RecoveryFilesystemError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _no_follow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _regular(metadata: os.stat_result, mode: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == mode
    )


def _parts(root: Path, path: Path) -> tuple[str, ...]:
    if not root.is_absolute() or not path.is_absolute():
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
    return relative.parts


def _validate_tree(value: Any, *, depth: int, nodes: list[int]) -> None:
    nodes[0] += 1
    if depth > MAX_JSON_DEPTH or nodes[0] > MAX_JSON_NODES:
        raise ValueError("json_tree_too_large")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("json_key_invalid")
            _validate_tree(child, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for child in value:
            _validate_tree(child, depth=depth + 1, nodes=nodes)


def _relative_parts(relative: tuple[str, ...]) -> tuple[str, ...]:
    """Validate a descriptor-relative path before it reaches ``openat``."""

    if type(relative) is not tuple or not relative:
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
    if any(
        type(component) is not str
        or not component
        or component in {".", ".."}
        or "/" in component
        or "\\" in component
        for component in relative
    ):
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
    return relative


@contextmanager
def pinned_root(root: Path, *, mode: int = 0o700) -> Iterator[int]:
    """Yield a pinned root FD; no pathname is trusted after opening it."""

    root_fd = -1
    current = -1
    try:
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | _no_follow())
        for component in root.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | _no_follow(),
                dir_fd=current,
            )
            os.close(current)
            current = child
        root_fd = current
        metadata = os.fstat(root_fd)
        if not _regular_directory(metadata, mode):
            raise RecoveryFilesystemError("post_c_recovery_root_invalid")
        yield root_fd
    except RecoveryFilesystemError:
        raise
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_root_invalid") from exc
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        elif current >= 0:
            os.close(current)


def _regular_directory(metadata: os.stat_result, mode: int) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == mode
    )


def validate_pinned_root(root_fd: int, *, mode: int = 0o700) -> tuple[int, int]:
    """Revalidate a previously pinned directory without following its path."""

    metadata = os.fstat(root_fd)
    if not _regular_directory(metadata, mode):
        raise RecoveryFilesystemError("post_c_recovery_root_replaced")
    return metadata.st_dev, metadata.st_ino


@contextmanager
def _open_parent(root_fd: int, parts: tuple[str, ...]) -> Iterator[tuple[int, str]]:
    current = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | _no_follow(),
                    dir_fd=current,
                )
                metadata = os.fstat(child)
                if not _regular_directory(metadata, 0o700):
                    raise RecoveryFilesystemError("post_c_recovery_artifact_permissions_invalid")
            except RecoveryFilesystemError:
                raise
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise RecoveryFilesystemError("post_c_recovery_artifact_unreadable") from exc
            os.close(current)
            current = child
        yield current, parts[-1]
    finally:
        os.close(current)


def _read_fd(fd: int, *, maximum: int, mode: int) -> bytes:
    before = os.fstat(fd)
    if not _regular(before, mode) or before.st_size > maximum:
        raise RecoveryFilesystemError("post_c_recovery_artifact_permissions_invalid")
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(fd, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    after = os.fstat(fd)
    raw = b"".join(chunks)
    if (
        len(raw) > maximum
        or not _regular(after, mode)
        or before.st_ino != after.st_ino
        or before.st_dev != after.st_dev
        or before.st_size != after.st_size
    ):
        raise RecoveryFilesystemError("post_c_recovery_artifact_unreadable")
    return raw


def read_bytes(root_fd: int, root: Path, path: Path, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    parts = _parts(root, path)
    try:
        with _open_parent(root_fd, parts) as (parent_fd, name):
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | _no_follow(), dir_fd=parent_fd)
            try:
                return _read_fd(fd, maximum=maximum, mode=0o600)
            finally:
                os.close(fd)
    except FileNotFoundError as exc:
        raise RecoveryFilesystemError("post_c_recovery_artifact_unreadable") from exc
    except RecoveryFilesystemError:
        raise
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_artifact_unreadable") from exc


def read_optional_bytes(
    root_fd: int,
    root: Path,
    path: Path,
    *,
    maximum: int = MAX_JSON_BYTES,
    expected_identity: tuple[int, int] | None = None,
) -> bytes | None:
    """Read an optional descriptor-relative file without a preflight pathname check."""

    parts = _parts(root, path)
    try:
        if expected_identity is not None:
            metadata = os.fstat(root_fd)
            if (metadata.st_dev, metadata.st_ino) != expected_identity:
                raise RecoveryFilesystemError("post_c_recovery_root_replaced")
        with _open_parent(root_fd, parts) as (parent_fd, name):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | _no_follow(), dir_fd=parent_fd)
            except FileNotFoundError:
                return None
            try:
                return _read_fd(fd, maximum=maximum, mode=0o600)
            finally:
                os.close(fd)
    except FileNotFoundError:
        return None
    except RecoveryFilesystemError:
        raise
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_artifact_unreadable") from exc


class _RejectDuplicateKeys(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _RejectDuplicateKeys(key)
        result[key] = value
    return result


def read_json(
    root_fd: int,
    root: Path,
    path: Path,
    *,
    maximum: int = MAX_JSON_BYTES,
    require_canonical: bool = True,
    approved_raw_sha256: str | None = None,
    require_object: bool = True,
) -> tuple[Any, bytes]:
    raw = read_bytes(root_fd, root, path, maximum=maximum)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        if require_object and not isinstance(value, dict):
            raise ValueError("object required")
        _validate_tree(value, depth=0, nodes=[0])
        canonical = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        approved_legacy = (
            approved_raw_sha256 is not None and sha256(raw).hexdigest() == approved_raw_sha256
        )
        if require_canonical and raw != canonical and not approved_legacy:
            raise ValueError("noncanonical")
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise RecoveryFilesystemError("post_c_recovery_artifact_invalid") from exc
    return value, raw


def list_children(root_fd: int) -> tuple[str, ...]:
    try:
        names = tuple(os.listdir(root_fd))
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_root_invalid") from exc
    return names


def ensure_empty_output_root(root: Path) -> None:
    """Require, but never create or chmod, the separately authorized output root."""

    try:
        metadata = root.lstat()
        if not _regular_directory(metadata, 0o700):
            raise RecoveryFilesystemError("post_c_recovery_output_root_invalid")
        if tuple(root.iterdir()):
            raise RecoveryFilesystemError("post_c_recovery_output_root_not_empty")
    except FileNotFoundError as exc:
        raise RecoveryFilesystemError("post_c_recovery_output_root_invalid") from exc
    except RecoveryFilesystemError:
        raise
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_output_root_invalid") from exc


def write_no_replace(
    root: Path,
    relative: tuple[str, ...],
    payload: bytes,
    *,
    expected_identity: tuple[int, int] | None = None,
    expected_leaf: str | None = None,
    expected_directory: str | None = "post-c",
    allowed_leaves: frozenset[str] | None = None,
) -> None:
    relative = _relative_parts(relative)
    if len(payload) > MAX_SEAL_BYTES:
        raise RecoveryFilesystemError("post_c_recovery_output_too_large")
    try:
        with pinned_root(root) as root_fd:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
            try:
                _write_no_replace_locked(
                    root_fd,
                    root,
                    relative,
                    payload,
                    expected_identity=expected_identity,
                    expected_leaf=expected_leaf,
                    expected_directory=expected_directory,
                    allowed_leaves=allowed_leaves,
                )
            finally:
                fcntl.flock(root_fd, fcntl.LOCK_UN)
    except RecoveryFilesystemError:
        raise
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_output_failed") from exc


def _write_no_replace_locked(
    root_fd: int,
    root: Path,
    relative: tuple[str, ...],
    payload: bytes,
    *,
    expected_identity: tuple[int, int] | None,
    expected_leaf: str | None,
    expected_directory: str | None,
    allowed_leaves: frozenset[str] | None,
) -> None:
    if expected_identity is not None:
        metadata = os.fstat(root_fd)
        if (metadata.st_dev, metadata.st_ino) != expected_identity:
            raise RecoveryFilesystemError("post_c_recovery_root_replaced")
    current = os.dup(root_fd)
    try:
        _validate_output_entries(
            root_fd,
            relative,
            expected_leaf=expected_leaf,
            expected_directory=expected_directory,
            allowed_leaves=allowed_leaves,
        )
        for component in relative[:-1]:
            try:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | _no_follow(),
                    dir_fd=current,
                )
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=current)
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | _no_follow(),
                    dir_fd=current,
                )
                os.fchmod(child, 0o700)
                os.fsync(current)
            if not _regular_directory(os.fstat(child), 0o700):
                raise RecoveryFilesystemError("post_c_recovery_output_conflict") from None
            os.close(current)
            current = child
        name = relative[-1]
        _validate_output_entries(
            root_fd,
            relative,
            expected_leaf=expected_leaf,
            expected_directory=expected_directory,
            allowed_leaves=allowed_leaves,
        )
        temporary_name = f".recovery-{os.getpid()}-{time.time_ns()}"
        temporary_fd: int | None = None
        for attempt in range(8):
            candidate = temporary_name if attempt == 0 else f"{temporary_name}-{attempt}"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | _no_follow(),
                    0o600,
                    dir_fd=current,
                )
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd is None:
            raise RecoveryFilesystemError("post_c_recovery_output_failed")
        try:
            try:
                os.fchmod(temporary_fd, 0o600)
                written = 0
                while written < len(payload):
                    written += os.write(temporary_fd, payload[written:])
                os.fsync(temporary_fd)
            except BaseException:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=current)
                raise
        finally:
            os.close(temporary_fd)
        try:
            os.link(
                temporary_name,
                name,
                src_dir_fd=current,
                dst_dir_fd=current,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | _no_follow(), dir_fd=current)
            try:
                existing = _read_fd(existing_fd, maximum=MAX_SEAL_BYTES, mode=0o600)
            finally:
                os.close(existing_fd)
            if existing != payload:
                raise RecoveryFilesystemError("post_c_recovery_output_conflict") from None
            return
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=current)
        os.fsync(current)
        os.fsync(root_fd)
    finally:
        os.close(current)


def _validate_output_entries(
    root_fd: int,
    relative: tuple[str, ...],
    *,
    expected_leaf: str | None,
    expected_directory: str | None,
    allowed_leaves: frozenset[str] | None,
) -> None:
    """Reject unexpected output entries while the root FD is pinned."""

    if not relative:
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
    if expected_directory is None:
        if len(relative) != 1:
            raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
        allowed = allowed_leaves or frozenset()
        try:
            names = set(os.listdir(root_fd))
            if names - allowed:
                raise RecoveryFilesystemError("post_c_recovery_output_conflict")
        except RecoveryFilesystemError:
            raise
        except OSError as exc:
            raise RecoveryFilesystemError("post_c_recovery_output_conflict") from exc
        return
    if relative[0] != expected_directory or len(relative) != 2:
        raise RecoveryFilesystemError("post_c_recovery_artifact_path_invalid")
    try:
        names = set(os.listdir(root_fd))
        if names - {expected_directory}:
            raise RecoveryFilesystemError("post_c_recovery_output_conflict")
        try:
            directory_fd = os.open(
                expected_directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | _no_follow(),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            if names:
                raise RecoveryFilesystemError("post_c_recovery_output_conflict") from None
            return
        try:
            metadata = os.fstat(directory_fd)
            if not _regular_directory(metadata, 0o700):
                raise RecoveryFilesystemError("post_c_recovery_output_conflict")
            leaves = set(os.listdir(directory_fd))
            allowed_leaves_set: set[str] = {expected_leaf} if expected_leaf is not None else set()
            if leaves - allowed_leaves_set:
                raise RecoveryFilesystemError("post_c_recovery_output_conflict")
        finally:
            os.close(directory_fd)
    except RecoveryFilesystemError:
        raise
    except OSError as exc:
        raise RecoveryFilesystemError("post_c_recovery_output_conflict") from exc


__all__ = [
    "MAX_JSON_BYTES",
    "MAX_SEAL_BYTES",
    "RecoveryFilesystemError",
    "ensure_empty_output_root",
    "list_children",
    "pinned_root",
    "read_bytes",
    "read_json",
    "read_optional_bytes",
    "write_no_replace",
]
