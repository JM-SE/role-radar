#!/usr/bin/env python3
"""Read-only path-specific preflight for the reviewed canary helper install."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath

TARGET = PurePosixPath("/opt/role-radar/scripts/bounded_canary_preflight.py")
BACKUP = PurePosixPath("/root/role-radar-preflight-status-3c3ec2a23026d05868e7951f34fbeb09")
CANDIDATE = Path(__file__).absolute().with_name("bounded_canary_preflight.py")
EXPECTED_PREIMAGE_SHA256 = "56378fab18a5aee17b62bdd6a12de695c916ab09c9ed85e45d658710bf1ffe1a"
EXPECTED_CANDIDATE_SHA256 = "3c3ec2a23026d05868e7951f34fbeb09d90b2bdaae1c1236e4a3c2da39f634ea"
TARGET_OWNER = (0, 0)
MAX_SOURCE_BYTES = 2_000_000
DIRECTORY_POLICY = {
    "/": (0, 0, 0o755),
    "/opt": (0, 0, 0o755),
    "/opt/role-radar": (1000, 1000, 0o755),
    "/opt/role-radar/scripts": (0, 0, 0o755),
    "/root": (0, 0, 0o700),
}


class PreflightError(Exception):
    """A fixed public preflight failure code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _close(fs, descriptors: list[int]) -> None:
    for descriptor in reversed(descriptors):
        with contextlib.suppress(OSError):
            fs.close(descriptor)


def _directory_identity(info) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
    )


def _file_identity(info) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _check_directory(info, logical_path: str, policy: dict[str, tuple[int, int, int]]) -> None:
    expected = policy.get(logical_path)
    actual = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or expected is None
        or actual != expected
    ):
        raise PreflightError("directory_metadata_mismatch")


def _open_chain(fs, root, components, policy):
    flags = fs.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0)
    descriptors = []
    identities = []
    logical_path = "/"
    try:
        descriptor = fs.open(os.fspath(root), flags)
        descriptors.append(descriptor)
        info = fs.fstat(descriptor)
        _check_directory(info, logical_path, policy)
        identities.append(_directory_identity(info))
        for component in components:
            if component in ("", ".", "..") or "/" in component:
                raise PreflightError("path_component_invalid")
            descriptor = fs.open(component, flags, dir_fd=descriptors[-1])
            descriptors.append(descriptor)
            logical_path = str(PurePosixPath(logical_path) / component)
            info = fs.fstat(descriptor)
            _check_directory(info, logical_path, policy)
            identities.append(_directory_identity(info))
        return descriptors, tuple(identities)
    except PreflightError:
        _close(fs, descriptors)
        raise
    except Exception:
        _close(fs, descriptors)
        raise PreflightError("filesystem_proof_unavailable") from None


def _revalidate_chain(fs, root, components, policy, expected):
    descriptors, identities = _open_chain(fs, root, components, policy)
    try:
        if identities != expected:
            raise PreflightError("parent_chain_changed")
    finally:
        _close(fs, descriptors)


def _read_hash(fs, path, *, required_owner=None, required_mode=None):
    flags = fs.O_RDONLY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NONBLOCK", 0)
    descriptor = None
    try:
        before = fs.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > MAX_SOURCE_BYTES
        ):
            raise PreflightError("source_metadata_mismatch")
        if required_owner is not None and (before.st_uid, before.st_gid) != required_owner:
            raise PreflightError("source_metadata_mismatch")
        if required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode:
            raise PreflightError("source_metadata_mismatch")
        descriptor = fs.open(os.fspath(path), flags)
        opened = fs.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise PreflightError("source_changed_during_open")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = fs.read(descriptor, min(65536, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise PreflightError("source_size_invalid")
            digest.update(chunk)
        after = fs.fstat(descriptor)
        named = fs.stat(path, follow_symlinks=False)
        if _file_identity(opened) != _file_identity(after) or _file_identity(
            after
        ) != _file_identity(named):
            raise PreflightError("source_changed_during_read")
        return digest.hexdigest()
    except PreflightError:
        raise
    except Exception:
        raise PreflightError("source_unavailable") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                fs.close(descriptor)


def _backup_absent(fs, descriptor: int) -> None:
    try:
        fs.stat(BACKUP.name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    except Exception:
        raise PreflightError("backup_destination_unavailable") from None
    raise PreflightError("backup_destination_exists")


def _read_target(fs, descriptor: int, expected_owner: tuple[int, int]) -> str:
    flags = fs.O_RDONLY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NONBLOCK", 0)
    name = TARGET.name
    source = None
    try:
        before = fs.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink)
            != (*expected_owner, 0o644, 1)
            or before.st_size < 0
            or before.st_size > MAX_SOURCE_BYTES
        ):
            raise PreflightError("target_metadata_mismatch")
        source = fs.open(name, flags, dir_fd=descriptor)
        opened = fs.fstat(source)
        if _file_identity(before) != _file_identity(opened):
            raise PreflightError("target_changed_during_open")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = fs.read(source, min(65536, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise PreflightError("target_size_invalid")
            digest.update(chunk)
        after = fs.fstat(source)
        named = fs.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if _file_identity(opened) != _file_identity(after) or (
            _file_identity(after) != _file_identity(named)
        ):
            raise PreflightError("target_changed_during_read")
        return digest.hexdigest()
    except PreflightError:
        raise
    except Exception:
        raise PreflightError("target_unavailable") from None
    finally:
        if source is not None:
            with contextlib.suppress(OSError):
                fs.close(source)


def _preflight(
    fs,
    root,
    directory_policy,
    candidate_path,
    expected_candidate_sha256,
    expected_preimage_sha256,
    expected_target_owner,
) -> None:
    candidate_digest = _read_hash(fs, candidate_path)
    if candidate_digest != expected_candidate_sha256:
        raise PreflightError("candidate_hash_mismatch")

    target_components = TARGET.parent.parts[1:]
    backup_components = BACKUP.parent.parts[1:]
    target_fds, target_ids = _open_chain(fs, root, target_components, directory_policy)
    backup_fds = []
    try:
        backup_fds, backup_ids = _open_chain(fs, root, backup_components, directory_policy)
        _revalidate_chain(fs, root, target_components, directory_policy, target_ids)
        _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
        _backup_absent(fs, backup_fds[-1])
        preimage_digest = _read_target(fs, target_fds[-1], expected_target_owner)
        if preimage_digest != expected_preimage_sha256:
            raise PreflightError("target_preimage_mismatch")
        _revalidate_chain(fs, root, target_components, directory_policy, target_ids)
        _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
        _backup_absent(fs, backup_fds[-1])
    finally:
        _close(fs, backup_fds)
        _close(fs, target_fds)


def main(
    argv=None,
    *,
    fs=os,
    root=Path("/"),
    directory_policy=None,
    candidate_path=CANDIDATE,
    expected_candidate_sha256=EXPECTED_CANDIDATE_SHA256,
    expected_preimage_sha256=EXPECTED_PREIMAGE_SHA256,
    expected_target_owner=TARGET_OWNER,
) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only preflight for one reviewed canary helper installation."
    )
    args = sys.argv[1:] if argv is None else argv
    parser.parse_args(args)
    policy = DIRECTORY_POLICY if directory_policy is None else directory_policy
    try:
        _preflight(
            fs,
            root,
            policy,
            candidate_path,
            expected_candidate_sha256,
            expected_preimage_sha256,
            expected_target_owner,
        )
    except PreflightError as exc:
        print(f"INSTALL_PREFLIGHT: FAIL ({exc.code})")
        return 1
    print("INSTALL_PREFLIGHT: PASS (read-only; target preimage and backup path verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
