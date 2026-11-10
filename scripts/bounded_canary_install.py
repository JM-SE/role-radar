#!/usr/bin/env python3
"""Install one reviewed canary parser with a protected exact preimage."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath

from scripts import bounded_canary_artifacts as artifacts

TARGET = PurePosixPath("/opt/role-radar/scripts/bounded_canary_preflight.py")
BACKUP = PurePosixPath("/root/role-radar-preflight-status-3c3ec2a23026d05868e7951f34fbeb09")
BACKUP_FILE_NAME = TARGET.name
STAGE_FILE_NAME = ".bounded_canary_preflight.py.install-3c3ec2a23026d05868e7951f34fbeb09"
CANDIDATE = Path(__file__).absolute().with_name(TARGET.name)
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


class InstallError(Exception):
    """Fixed public failure code; never exposes path or filesystem details."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _identity(info) -> tuple[int, ...]:
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


def _directory_identity(info) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
    )


def _close(fs, descriptors: list[int]) -> None:
    for descriptor in reversed(descriptors):
        with contextlib.suppress(OSError):
            fs.close(descriptor)


def _require_directory(info, logical_path: str, policy) -> None:
    expected = policy.get(logical_path)
    actual = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or expected is None
        or actual != expected
    ):
        raise InstallError("directory_metadata_mismatch")


def _open_chain(fs, root, components, policy):
    flags = fs.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0)
    descriptors = []
    identities = []
    logical_path = "/"
    try:
        descriptor = fs.open(os.fspath(root), flags)
        descriptors.append(descriptor)
        info = fs.fstat(descriptor)
        _require_directory(info, logical_path, policy)
        identities.append(_directory_identity(info))
        for component in components:
            if component in ("", ".", "..") or "/" in component:
                raise InstallError("path_component_invalid")
            descriptor = fs.open(component, flags, dir_fd=descriptors[-1])
            descriptors.append(descriptor)
            logical_path = str(PurePosixPath(logical_path) / component)
            info = fs.fstat(descriptor)
            _require_directory(info, logical_path, policy)
            identities.append(_directory_identity(info))
        return descriptors, tuple(identities)
    except InstallError:
        _close(fs, descriptors)
        raise
    except Exception:
        _close(fs, descriptors)
        raise InstallError("filesystem_proof_unavailable") from None


def _revalidate_chain(fs, root, components, policy, expected) -> None:
    descriptors, identities = _open_chain(fs, root, components, policy)
    try:
        if identities != expected:
            raise InstallError("parent_chain_changed")
    finally:
        _close(fs, descriptors)


def _read_path(fs, path, *, owner=None, mode=None) -> tuple[bytes, tuple[int, ...]]:
    flags = fs.O_RDONLY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NONBLOCK", 0)
    descriptor = None
    try:
        before = fs.stat(path, follow_symlinks=False)
        _check_file(before, owner=owner, mode=mode, error="candidate_metadata_mismatch")
        descriptor = fs.open(os.fspath(path), flags)
        return _read_open_file(fs, descriptor, path, None, before, owner, mode, "candidate")
    except InstallError:
        raise
    except Exception:
        raise InstallError("candidate_unavailable") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                fs.close(descriptor)


def _check_file(info, *, owner, mode, error: str) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_size < 0
        or info.st_size > MAX_SOURCE_BYTES
        or (owner is not None and (info.st_uid, info.st_gid) != owner)
        or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
    ):
        raise InstallError(error)


def _read_open_file(fs, descriptor, path, parent_fd, before, owner, mode, label):
    error = f"{label}_changed_during_open"
    try:
        opened = fs.fstat(descriptor)
        _check_file(opened, owner=owner, mode=mode, error=error)
        if _identity(before) != _identity(opened):
            raise InstallError(error)
        chunks = bytearray()
        total = 0
        while True:
            chunk = fs.read(descriptor, min(65536, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise InstallError(f"{label}_size_invalid")
            chunks.extend(chunk)
        after = fs.fstat(descriptor)
        if parent_fd is None:
            named = fs.stat(path, follow_symlinks=False)
        else:
            named = fs.stat(path, dir_fd=parent_fd, follow_symlinks=False)
        if (
            total != opened.st_size
            or _identity(opened) != _identity(after)
            or _identity(after) != _identity(named)
        ):
            raise InstallError(f"{label}_changed_during_read")
        return bytes(chunks), _identity(after)
    except InstallError:
        raise
    except Exception:
        raise InstallError(f"{label}_unavailable") from None


def _read_at(fs, parent_fd: int, name: str, *, owner, mode, label: str):
    flags = fs.O_RDONLY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0) | getattr(fs, "O_NONBLOCK", 0)
    descriptor = None
    try:
        before = fs.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _check_file(before, owner=owner, mode=mode, error=f"{label}_metadata_mismatch")
        descriptor = fs.open(name, flags, dir_fd=parent_fd)
        return _read_open_file(fs, descriptor, name, parent_fd, before, owner, mode, label)
    except InstallError:
        raise
    except Exception:
        raise InstallError(f"{label}_unavailable") from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                fs.close(descriptor)


def _absent(fs, parent_fd: int, name: str, code: str) -> None:
    try:
        fs.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except Exception:
        raise InstallError(f"{code}_unavailable") from None
    raise InstallError(f"{code}_exists")


def _create_directory(fs, parent_fd: int, name: str, owner) -> int:
    descriptor = None
    keep_open = False
    try:
        fs.mkdir(name, 0o700, dir_fd=parent_fd)
        descriptor = fs.open(
            name,
            fs.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW | getattr(fs, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        fs.fchown(descriptor, *owner)
        fs.fchmod(descriptor, 0o700)
        created = fs.fstat(descriptor)
        named = fs.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(created.st_mode)
            or _directory_identity(created) != _directory_identity(named)
            or (created.st_uid, created.st_gid, stat.S_IMODE(created.st_mode)) != (*owner, 0o700)
        ):
            raise InstallError("backup_outcome_uncertain")
        keep_open = True
        return descriptor
    except InstallError:
        raise
    except Exception:
        raise InstallError("backup_outcome_uncertain") from None
    finally:
        if descriptor is not None and not keep_open:
            with contextlib.suppress(OSError):
                fs.close(descriptor)


def _require_named_directory(fs, parent_fd, name, descriptor, owner, mode) -> None:
    try:
        opened = fs.fstat(descriptor)
        named = fs.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _directory_identity(opened) != _directory_identity(named)
            or (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (*owner, mode)
        ):
            raise InstallError("backup_outcome_uncertain")
    except InstallError:
        raise
    except Exception:
        raise InstallError("backup_outcome_uncertain") from None


def _artifact_owner(info, uid, gid) -> None:
    if (info.st_uid, info.st_gid) != (uid, gid):
        raise artifacts.ArtifactError("artifact_metadata_invalid")


def _write_new_file_at(fs, parent_fd, name, data, *, owner, mode, code, validate_parent):
    try:
        return artifacts.write_new_at(
            parent_fd,
            name,
            data,
            uid=owner[0],
            gid=owner[1],
            mode=mode,
            chown=lambda descriptor, uid, gid: fs.fchown(descriptor, uid, gid),
            require_owner=_artifact_owner,
            validate_parent=validate_parent,
        )
    except Exception:
        raise InstallError(code) from None


def _install(
    fs,
    root,
    directory_policy,
    candidate_path,
    expected_candidate_sha256,
    expected_preimage_sha256,
    expected_target_owner,
) -> None:
    candidate, _candidate_identity = _read_path(fs, candidate_path)
    if hashlib.sha256(candidate).hexdigest() != expected_candidate_sha256:
        raise InstallError("candidate_hash_mismatch")

    target_components = TARGET.parent.parts[1:]
    backup_components = BACKUP.parent.parts[1:]
    target_fds, target_ids = _open_chain(fs, root, target_components, directory_policy)
    backup_fds = []
    try:
        backup_fds, backup_ids = _open_chain(fs, root, backup_components, directory_policy)
        _revalidate_chain(fs, root, target_components, directory_policy, target_ids)
        _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
        _absent(fs, backup_fds[-1], BACKUP.name, "backup_destination")
        _absent(fs, target_fds[-1], STAGE_FILE_NAME, "stage_destination")
        preimage, preimage_identity = _read_at(
            fs,
            target_fds[-1],
            TARGET.name,
            owner=expected_target_owner,
            mode=0o644,
            label="target",
        )
        if hashlib.sha256(preimage).hexdigest() != expected_preimage_sha256:
            raise InstallError("target_preimage_mismatch")

        backup_fds.append(_create_directory(fs, backup_fds[-1], BACKUP.name, expected_target_owner))

        def validate_backup_parent():
            _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
            _require_named_directory(
                fs, backup_fds[-2], BACKUP.name, backup_fds[-1], expected_target_owner, 0o700
            )

        _write_new_file_at(
            fs,
            backup_fds[-1],
            BACKUP_FILE_NAME,
            preimage,
            owner=expected_target_owner,
            mode=0o600,
            code="backup_outcome_uncertain",
            validate_parent=validate_backup_parent,
        )
        try:
            fs.fsync(backup_fds[-1])
            fs.fsync(backup_fds[-2])
            validate_backup_parent()
            backed_up, _ = _read_at(
                fs,
                backup_fds[-1],
                BACKUP_FILE_NAME,
                owner=expected_target_owner,
                mode=0o600,
                label="backup",
            )
            if (
                backed_up != preimage
                or hashlib.sha256(backed_up).hexdigest() != expected_preimage_sha256
            ):
                raise InstallError("backup_outcome_uncertain")
        except InstallError:
            raise
        except Exception:
            raise InstallError("backup_outcome_uncertain") from None

        _revalidate_chain(fs, root, target_components, directory_policy, target_ids)
        _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
        candidate, _ = _read_path(fs, candidate_path)
        if hashlib.sha256(candidate).hexdigest() != expected_candidate_sha256:
            raise InstallError("candidate_hash_mismatch")
        current_target, current_identity = _read_at(
            fs,
            target_fds[-1],
            TARGET.name,
            owner=expected_target_owner,
            mode=0o644,
            label="target",
        )
        if current_target != preimage or current_identity != preimage_identity:
            raise InstallError("target_changed_before_install")
        _absent(fs, target_fds[-1], STAGE_FILE_NAME, "stage_destination")

        def validate_target_parent():
            _revalidate_chain(fs, root, target_components, directory_policy, target_ids)

        staged_identity = _write_new_file_at(
            fs,
            target_fds[-1],
            STAGE_FILE_NAME,
            candidate,
            owner=expected_target_owner,
            mode=0o644,
            code="stage_outcome_uncertain",
            validate_parent=validate_target_parent,
        )
        staged_bytes, staged_identity_after = _read_at(
            fs,
            target_fds[-1],
            STAGE_FILE_NAME,
            owner=expected_target_owner,
            mode=0o644,
            label="stage",
        )
        if (
            staged_bytes != candidate
            or hashlib.sha256(staged_bytes).hexdigest() != expected_candidate_sha256
            or staged_identity_after[:2] != staged_identity[:2]
        ):
            raise InstallError("stage_outcome_uncertain")
        _revalidate_chain(fs, root, target_components, directory_policy, target_ids)
        _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
        current_target, current_identity = _read_at(
            fs,
            target_fds[-1],
            TARGET.name,
            owner=expected_target_owner,
            mode=0o644,
            label="target",
        )
        if current_target != preimage or current_identity != preimage_identity:
            raise InstallError("target_changed_before_install")
        stage_named = fs.stat(STAGE_FILE_NAME, dir_fd=target_fds[-1], follow_symlinks=False)
        if (stage_named.st_dev, stage_named.st_ino) != staged_identity[:2]:
            raise InstallError("stage_outcome_uncertain")
        _require_named_directory(
            fs, backup_fds[-2], BACKUP.name, backup_fds[-1], expected_target_owner, 0o700
        )
        try:
            fs.replace(
                STAGE_FILE_NAME,
                TARGET.name,
                src_dir_fd=target_fds[-1],
                dst_dir_fd=target_fds[-1],
            )
        except Exception:
            raise InstallError("install_outcome_uncertain") from None
        try:
            fs.fsync(target_fds[-1])
            installed, _ = _read_at(
                fs,
                target_fds[-1],
                TARGET.name,
                owner=expected_target_owner,
                mode=0o644,
                label="installed",
            )
            if (
                installed != candidate
                or hashlib.sha256(installed).hexdigest() != expected_candidate_sha256
            ):
                raise InstallError("install_outcome_uncertain")
            _absent(fs, target_fds[-1], STAGE_FILE_NAME, "stage_after_install")
            backed_up, _ = _read_at(
                fs,
                backup_fds[-1],
                BACKUP_FILE_NAME,
                owner=expected_target_owner,
                mode=0o600,
                label="backup",
            )
            if (
                backed_up != preimage
                or hashlib.sha256(backed_up).hexdigest() != expected_preimage_sha256
            ):
                raise InstallError("install_outcome_uncertain")
            _require_named_directory(
                fs, backup_fds[-2], BACKUP.name, backup_fds[-1], expected_target_owner, 0o700
            )
            _revalidate_chain(fs, root, target_components, directory_policy, target_ids)
            _revalidate_chain(fs, root, backup_components, directory_policy, backup_ids)
        except Exception:
            raise InstallError("install_outcome_uncertain") from None
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
    require_root: bool = True,
) -> int:
    parser = argparse.ArgumentParser(description="Install the one reviewed canary parser artifact.")
    args = sys.argv[1:] if argv is None else argv
    parser.parse_args(args)
    policy = DIRECTORY_POLICY if directory_policy is None else directory_policy
    try:
        if require_root and fs is os and os.geteuid() != 0:
            raise InstallError("root_required")
        _install(
            fs,
            root,
            policy,
            candidate_path,
            expected_candidate_sha256,
            expected_preimage_sha256,
            expected_target_owner,
        )
    except InstallError as exc:
        print(f"PARSER_INSTALL: FAIL ({exc.code})")
        return 1
    except Exception:
        print("PARSER_INSTALL: FAIL (install_outcome_uncertain)")
        return 1
    print("PARSER_INSTALL: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
