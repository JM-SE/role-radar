#!/usr/bin/env python3
"""Create one protected, consistent canary backup; never creates or starts a run."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path

from scripts import bounded_canary_artifacts as artifacts
from scripts import bounded_canary_binding as binding
from scripts import bounded_canary_database as database
from scripts import bounded_canary_preflight as preflight
from scripts import bounded_canary_provenance as provenance

ENV_PATH = Path("/etc/role-radar/role-radar.env")
POLICY_PATH = Path("/etc/role-radar/discovery-policy.toml")
BACKUP_ROOT = Path("/opt/role-radar/data/backups")
DB_URL = "sqlite:///./data/role-radar.db"
DEADLINE_SECONDS = 20.0
CHUNK_PAGES = 128
MAX_CONFIG_BYTES = 2_000_000
SOURCE_PROOF_VERSION = 2
ROOT_MODE = 0o755
CHILD_MODE = 0o700
PRIVATE_MODE = 0o600
DIRFD_SUPPORT = {os.open, os.stat} <= os.supports_dir_fd


class BackupError(Exception):
    """A fixed public backup failure code."""

    def __init__(self, code: str, *, recovery_path: str | None = None,
                 creation_state: str | None = None):
        super().__init__(code)
        self.recovery_path = recovery_path
        self.creation_state = creation_state


def _require_root_operator() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise BackupError("operator_privilege_required")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _inode(info):
    return info.st_dev, info.st_ino


def _database_stat_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _capture_database_target(database_url: str) -> dict:
    parent_fds = []
    source_fd = None
    try:
        path = database._database_path(database_url)
        parent_fds, parent_ids = _open_chain(path.parent)
        source_fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fds[-1],
        )
        identity = database._file_identity(path)
        opened = os.fstat(source_fd)
        named = os.stat(path.name, dir_fd=parent_fds[-1], follow_symlinks=False)
        if (_database_stat_identity(opened) != identity[:6]
                or _database_stat_identity(named) != identity[:6]
                or not stat.S_ISREG(opened.st_mode)):
            raise BackupError("database_target_changed")
        return {"path": path, "identity": identity, "parent_fds": parent_fds,
                "parent_ids": parent_ids, "source_fd": source_fd}
    except BackupError:
        if source_fd is not None:
            os.close(source_fd)
        _close_all(parent_fds)
        raise
    except Exception:
        if source_fd is not None:
            os.close(source_fd)
        _close_all(parent_fds)
        raise BackupError("database_target_changed") from None


def _close_database_target(target) -> None:
    if target is not None:
        with suppress(OSError):
            os.close(target["source_fd"])
        _close_all(target["parent_fds"])


def _verify_database_target(target, connection=None) -> None:
    try:
        path = target["path"]
        if tuple(_inode(os.fstat(fd)) for fd in target["parent_fds"]) != target["parent_ids"]:
            raise BackupError("database_target_changed")
        current_fds, current_ids = _open_chain(path.parent)
        try:
            if current_ids != target["parent_ids"]:
                raise BackupError("database_target_changed")
        finally:
            _close_all(current_fds)
        opened = os.fstat(target["source_fd"])
        named = os.stat(path.name, dir_fd=target["parent_fds"][-1], follow_symlinks=False)
        if (_database_stat_identity(opened) != target["identity"][:6]
                or _database_stat_identity(named) != target["identity"][:6]
                or database._file_identity(path) != target["identity"]):
            raise BackupError("database_target_changed")
        if connection is not None:
            if (connection.target_path != path
                    or connection.target_identity != target["identity"]):
                raise BackupError("database_target_changed")
            database._verify_target_stable(connection)
    except BackupError:
        raise
    except Exception:
        raise BackupError("database_target_changed") from None


def _verify_gate_database_target(target, gates) -> None:
    if gates.get("database_target") != (target["path"], target["identity"]):
        raise BackupError("database_target_changed")
    _verify_database_target(target)


def _require_owner(info, uid: int, gid: int, code: str) -> None:
    if info.st_uid != uid or info.st_gid != gid:
        raise BackupError(code)


def _require_created_by_process(info, code: str) -> None:
    if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
        raise BackupError(code)


def _chown_new(fd: int, uid: int, gid: int) -> None:
    if not hasattr(os, "fchown"):
        raise BackupError("artifact_owner_unavailable")
    os.fchown(fd, uid, gid)


def _open_chain(path: Path):
    """Hold every nonsymlink directory from / through path, binding dev/inode."""
    if not path.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
        raise BackupError("filesystem_proof_unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptors = []
    try:
        fd = os.open("/", flags)
        descriptors.append(fd)
        identities = [_inode(os.fstat(fd))]
        for component in path.parts[1:]:
            fd = os.open(component, flags, dir_fd=fd)
            descriptors.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise BackupError("backup_root_invalid")
            identities.append(_inode(info))
        return descriptors, tuple(identities)
    except BackupError:
        _close_all(descriptors)
        raise
    except Exception:
        _close_all(descriptors)
        raise BackupError("filesystem_proof_unavailable") from None


def _close_all(descriptors) -> None:
    for fd in reversed(descriptors):
        with suppress(OSError):
            os.close(fd)


def _revalidate_root(root_fds, root_ids) -> None:
    current, ids = _open_chain(BACKUP_ROOT)
    try:
        if ids != root_ids or _inode(os.fstat(root_fds[-1])) != root_ids[-1]:
            raise BackupError("backup_root_changed")
    finally:
        _close_all(current)


def _check_root(root_fd) -> None:
    info = os.fstat(root_fd)
    _require_owner(info, 0, 0, "backup_root_owner_invalid")
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != ROOT_MODE:
        raise BackupError("backup_root_invalid")


def _check_child(root_fd, child_fd, name: str) -> None:
    child = os.fstat(child_fd)
    path = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    _require_owner(child, 0, 0, "backup_child_owner_invalid")
    if (not stat.S_ISDIR(child.st_mode) or stat.S_IMODE(child.st_mode) != CHILD_MODE
            or _inode(child) != _inode(path) or _identity(child) != _identity(path)):
        raise BackupError("backup_child_invalid")


def _require_no_symlink_support() -> None:
    required = ("O_NOFOLLOW", "O_DIRECTORY", "fstatvfs", "fchown", "fchmod")
    if any(not hasattr(os, name) for name in required):
        raise BackupError("filesystem_proof_unavailable")
    if not DIRFD_SUPPORT:
        raise BackupError("filesystem_proof_unavailable")
    try:
        fd = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.close(fd)
    except OSError:
        raise BackupError("sqlite_destination_unavailable") from None


def _fixed_file(
    path: Path, *, mode: int, gid: int
) -> tuple[bytes, tuple[int, ...], tuple[tuple[int, int], ...]]:
    """Read a bounded root-owned file via a nonsymlink descriptor chain."""
    dirs = []
    fd = None
    try:
        if not path.is_absolute() or not hasattr(os, "O_NOFOLLOW"):
            raise BackupError("config_unavailable")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        parent = os.open("/", flags)
        dirs.append(parent)
        chain = [_inode(os.fstat(parent))]
        for part in path.parts[1:-1]:
            parent = os.open(part, flags, dir_fd=parent)
            dirs.append(parent)
            chain.append(_inode(os.fstat(parent)))
        leaf = path.parts[-1]
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != mode
                or before.st_nlink != 1):
            raise BackupError("config_metadata_invalid")
        _require_owner(before, 0, gid, "config_metadata_invalid")
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     dir_fd=parent)
        opened = os.fstat(fd)
        if _identity(before) != _identity(opened):
            raise BackupError("config_changed")
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, MAX_CONFIG_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_CONFIG_BYTES:
                raise BackupError("config_size_invalid")
        after = os.fstat(fd)
        path_after = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if _identity(opened) != _identity(after) or _identity(after) != _identity(path_after):
            raise BackupError("config_changed")
        current, current_ids = _open_chain(path.parent)
        try:
            if current_ids != tuple(chain):
                raise BackupError("config_changed")
            current_file = os.stat(leaf, dir_fd=current[-1], follow_symlinks=False)
            if _identity(current_file) != _identity(after):
                raise BackupError("config_changed")
        finally:
            _close_all(current)
        return bytes(data), _identity(after), tuple(chain)
    except BackupError:
        raise
    except Exception:
        raise BackupError("config_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)
        _close_all(dirs)


def _fresh_gates(database_url: str, systemd_runner=None) -> dict:
    run_id = str(uuid.uuid4())  # Probe only; the future run-create command owns its ID.
    try:
        preflight.run_gate(run_id, runner=systemd_runner)
        provenance.verify_sources()
        connection = database._connect_database(database_url)
        try:
            database._inspect(connection)
            history = database.snapshot_history(connection)
            database._verify_target_stable(connection)
            database_target = (connection.target_path, connection.target_identity)
        finally:
            connection.close()
        loaded = binding._load_policy(str(POLICY_PATH))
        connection = binding._connect_database(database_url)
        try:
            bound_profile_id = binding.inspect_binding(connection, loaded.policy)
            database._verify_target_stable(connection)
            if (connection.target_path, connection.target_identity) != database_target:
                raise BackupError("database_target_changed")
            current = binding._load_policy(str(POLICY_PATH))
            if (current.raw_bytes != loaded.raw_bytes
                    or current.policy_sha256 != loaded.policy_sha256):
                raise BackupError("policy_changed")
        finally:
            connection.close()
        return {"history": history, "probe_run_id": run_id,
                "policy_bytes": current.raw_bytes,
                "policy_sha256": current.policy_sha256,
                "database_target": database_target,
                "bound_profile_id": bound_profile_id}
    except BackupError:
        raise
    except Exception as exc:
        code = str(exc)
        gate_errors = {
            "producer_or_canary_active", "runtime_baseline_invalid",
            "canary_worker_contract_invalid", "systemd_proof_unavailable",
            "source_hash_mismatch", "source_metadata_invalid", "source_proof_unavailable",
            "database_target_changed", "database_integrity_invalid", "database_foreign_key_invalid",
            "database_schema_invalid", "schema_invalid", "schema_revision_invalid",
            "run_history_unresolved", "outbox_unresolved", "profile_binding_mismatch",
            "discovery_profile_binding_mismatch", "discovery_profile_invalid", "policy_changed",
        }
        if code in gate_errors:
            raise BackupError(code) from None
        raise BackupError("gate_unavailable") from None


def _available_bytes(root_fd) -> int:
    try:
        info = os.fstatvfs(root_fd)
        return info.f_bavail * info.f_frsize
    except Exception:
        raise BackupError("backup_capacity_unavailable") from None


def _required_bytes(database_url: str, env: bytes, policy: bytes) -> int:
    try:
        db_path = database._database_path(database_url)
        size = db_path.stat(follow_symlinks=False).st_size
        wal = Path(f"{db_path}-wal")
        try:
            wal_info = wal.lstat()
        except FileNotFoundError:
            wal_info = None
        if wal_info is not None:
            if not stat.S_ISREG(wal_info.st_mode):
                raise BackupError("backup_capacity_unavailable")
            size += wal_info.st_size
        return size + len(env) + len(policy) + 1_048_576
    except BackupError:
        raise
    except Exception:
        raise BackupError("backup_capacity_unavailable") from None


def _validate_child_path(root_fds, root_ids, root_fd, child_fd, name: str) -> None:
    _revalidate_root(root_fds, root_ids)
    _check_root(root_fd)
    _check_child(root_fd, child_fd, name)


def _artifact_owner(info, uid, gid):
    _require_owner(info, uid, gid, "artifact_metadata_invalid")


def _write_new_at(root_fds, root_ids, root_fd, child_fd, child_name, name, data: bytes):
    def validate():
        _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
    try:
        return artifacts.write_new_at(
            child_fd, name, data, uid=0, gid=0, mode=PRIVATE_MODE,
            chown=_chown_new, require_owner=_artifact_owner, validate_parent=validate,
        )
    except artifacts.ArtifactError as exc:
        raise BackupError(exc.code) from None
    except BackupError:
        raise
    except Exception:
        raise BackupError("artifact_write_failed") from None


def _verify_artifacts(root_fds, root_ids, root_fd, child_fd, child_name, identities):
    _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
    for name, expected in identities.items():
        info = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        _require_owner(info, 0, 0, "artifact_metadata_invalid")
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != PRIVATE_MODE
                or info.st_nlink != 1 or _inode(info) != expected):
            raise BackupError("artifact_metadata_invalid")


def _create_empty_at(root_fds, root_ids, root_fd, child_fd, child_name, name):
    def validate():
        _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
    try:
        return artifacts.create_empty_at(
            child_fd, name, uid=0, gid=0, mode=PRIVATE_MODE,
            chown=_chown_new, require_owner=_artifact_owner, validate_parent=validate,
        )
    except artifacts.ArtifactError as exc:
        raise BackupError(exc.code) from None
    except BackupError:
        raise
    except Exception:
        raise BackupError("artifact_write_failed") from None


def _verify_source_config(
    path, expected_data, expected_identity, expected_chain, *, mode, gid
) -> None:
    actual, identity, chain = _fixed_file(path, mode=mode, gid=gid)
    if (actual != expected_data or identity != expected_identity
            or chain != expected_chain):
        raise BackupError("config_changed")


def _private_artifact_digest(child_fd, name: str) -> tuple[str, tuple[int, ...]]:
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     dir_fd=child_fd)
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        _require_owner(info, 0, 0, "artifact_metadata_invalid")
        if (not stat.S_ISREG(info.st_mode) or _identity(info) != _identity(named)
                or stat.S_IMODE(info.st_mode) != PRIVATE_MODE or info.st_nlink != 1):
            raise BackupError("artifact_metadata_invalid")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        if _identity(info) != _identity(after) or _identity(after) != _identity(named_after):
            raise BackupError("artifact_changed")
        return digest.hexdigest(), _identity(after)
    except BackupError:
        raise
    except Exception:
        raise BackupError("artifact_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _source_proof(database_target, env_identity, env_chain, policy_identity, policy_chain,
                  child_fd) -> dict:
    database_hash, database_copy_identity = _private_artifact_digest(child_fd, "role-radar.db")
    history_hash, _ = _private_artifact_digest(child_fd, "history.json")
    env_hash, _ = _private_artifact_digest(child_fd, "role-radar.env")
    policy_hash, _ = _private_artifact_digest(child_fd, "discovery-policy.toml")
    database_stat = os.fstat(database_target["source_fd"])
    return {
        "schema_version": SOURCE_PROOF_VERSION,
        "source": {
            "database": {
                "path": str(database_target["path"]),
                "identity": list(database_target["identity"]),
                "ownership": [database_stat.st_uid, database_stat.st_gid, database_stat.st_nlink],
                "parent_identities": [list(item) for item in database_target["parent_ids"]],
            },
            "environment": {
                "path": str(ENV_PATH), "identity": list(env_identity),
                "parent_identities": [list(item) for item in env_chain],
                "sha256": env_hash,
            },
            "policy": {
                "path": str(POLICY_PATH), "identity": list(policy_identity),
                "parent_identities": [list(item) for item in policy_chain],
                "sha256": policy_hash,
            },
        },
        "backup": {
            "database_sha256": database_hash, "database_identity": list(database_copy_identity),
            "history_sha256": history_hash, "environment_sha256": env_hash,
            "policy_sha256": policy_hash,
        },
    }


def _sync_child(root_fds, root_ids, root_fd, child_fd, child_name) -> None:
    _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
    os.fsync(child_fd)


def _backup_database(database_url: str, root_fds, root_ids, root_fd, child_fd,
                     child_name: str, dest_fd: int, dest_identity,
                     expected_history=None, database_target=None) -> dict:
    source = None
    target = None
    started = time.monotonic()
    destination_name = "role-radar.db"
    try:
        if database_target is not None:
            _verify_database_target(database_target)
        source = database._connect_database(database_url)
        if database_target is not None:
            _verify_database_target(database_target, source)
        database._inspect(source)
        before = database.snapshot_history(source)
        if expected_history is not None and before != expected_history:
            raise BackupError("database_history_changed")
        _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
        destination_path = os.stat(destination_name, dir_fd=child_fd, follow_symlinks=False)
        if (_inode(destination_path) != dest_identity
                or _inode(os.fstat(dest_fd)) != dest_identity):
            raise BackupError("artifact_changed")
        uri = f"file:/proc/self/fd/{dest_fd}?mode=rw"
        target = sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)
        if target.execute("PRAGMA journal_mode=MEMORY").fetchone() != ("memory",):
            raise BackupError("sqlite_destination_unavailable")
        target.execute("PRAGMA query_only=OFF")
        destination_path = os.stat(destination_name, dir_fd=child_fd, follow_symlinks=False)
        if _inode(destination_path) != dest_identity:
            raise BackupError("artifact_changed")
        expired = False

        def progress(_status, _remaining, _total):
            nonlocal expired
            if time.monotonic() - started > DEADLINE_SECONDS:
                expired = True
                raise BackupError("backup_deadline")

        try:
            try:
                artifacts.verify_file(
                    dest_fd, child_fd, destination_name, dest_identity, uid=0, gid=0,
                    mode=PRIVATE_MODE, require_owner=_artifact_owner,
                    validate_parent=lambda: _validate_child_path(
                        root_fds, root_ids, root_fd, child_fd, child_name
                    ),
                )
            except artifacts.ArtifactError as exc:
                raise BackupError(exc.code) from None
            source.backup(target, pages=CHUNK_PAGES, progress=progress, sleep=0.05)
            if database_target is not None:
                _verify_database_target(database_target, source)
        except Exception:
            if expired or time.monotonic() - started > DEADLINE_SECONDS:
                raise BackupError("backup_deadline") from None
            raise
        if expired or time.monotonic() - started > DEADLINE_SECONDS:
            raise BackupError("backup_deadline")
        target.execute("PRAGMA query_only=ON")
        database._inspect(target)
        after = database.snapshot_history(target)
        if before != after:
            raise BackupError("history_snapshot_mismatch")
        if database._rows(target, "PRAGMA integrity_check") != (("ok",),):
            raise BackupError("database_integrity_invalid")
        if database._rows(target, "PRAGMA foreign_key_check"):
            raise BackupError("database_foreign_key_invalid")
        target.close()
        target = None
        _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
        destination_path = os.stat(destination_name, dir_fd=child_fd, follow_symlinks=False)
        if _inode(destination_path) != dest_identity:
            raise BackupError("artifact_changed")
        os.fsync(dest_fd)
        final = os.fstat(dest_fd)
        path_final = os.stat(destination_name, dir_fd=child_fd, follow_symlinks=False)
        _require_owner(final, 0, 0, "artifact_metadata_invalid")
        if (_inode(final) != dest_identity or _identity(final) != _identity(path_final)
                or final.st_nlink != 1 or stat.S_IMODE(final.st_mode) != PRIVATE_MODE):
            raise BackupError("artifact_metadata_invalid")
        return after
    except BackupError:
        raise
    except Exception:
        raise BackupError("database_backup_failed") from None
    finally:
        try:
            if target is not None:
                target.close()
        finally:
            try:
                if source is not None:
                    source.close()
            finally:
                os.close(dest_fd)


def _artifact_state(name: str, attempted: set[str], completed: set[str]) -> str:
    if name in completed:
        return "created"
    if name in attempted:
        return "attempted"
    return "not_created"


def _write_partial(root_fds, root_ids, root_fd, child_fd, child_name, recovery,
                   states, failure):
    try:
        record = {"schema_version": 1, "state": "partial", "recovery_path": recovery,
                  "creation": "created", "failure": failure, **states}
        _write_new_at(root_fds, root_ids, root_fd, child_fd, child_name,
                      "partial.json", (json.dumps(record, sort_keys=True) + "\n").encode())
        _sync_child(root_fds, root_ids, root_fd, child_fd, child_name)
        os.fsync(root_fd)
    except Exception:
        pass


def _create_backup(database_url: str, *, systemd_runner=None) -> Path:
    child_name = f"canary-{secrets.token_hex(16)}"
    recovery = str(BACKUP_ROOT / child_name)
    database_target = None
    try:
        _require_root_operator()
        _require_no_symlink_support()
        database_target = _capture_database_target(database_url)
        root_fds, root_ids = _open_chain(BACKUP_ROOT)
    except BackupError as exc:
        _close_database_target(database_target)
        exc.recovery_path = recovery
        exc.creation_state = "not_created"
        raise
    root_fd = root_fds[-1]
    child_fd = None
    creation_state = "not_created"
    attempted, completed = set(), set()
    artifact_identities = {}
    planned_intent = {
        "schema_version": 1, "state": "attempted", "recovery_path": recovery,
        "creation": "planned", "database": "planned", "environment": "planned",
        "policy": "planned", "history": "planned",
    }
    try:
        _check_root(root_fd)
        _revalidate_root(root_fds, root_ids)
        env_gid = 0
        policy_file_policy = binding.production_discovery_policy_file_policy()
        if policy_file_policy.group_gid is None or policy_file_policy.group_gid < 0:
            raise BackupError("policy_metadata_unavailable")
        env_bytes, env_identity, env_chain = _fixed_file(
            ENV_PATH, mode=0o600, gid=env_gid
        )
        policy_bytes, policy_identity, policy_chain = _fixed_file(
            POLICY_PATH, mode=0o640, gid=policy_file_policy.group_gid
        )
        first = _fresh_gates(database_url, systemd_runner)
        _verify_gate_database_target(database_target, first)
        if policy_bytes != first["policy_bytes"]:
            raise BackupError("policy_changed")
        _verify_source_config(ENV_PATH, env_bytes, env_identity, env_chain,
                              mode=0o600, gid=env_gid)
        _verify_source_config(POLICY_PATH, policy_bytes, policy_identity, policy_chain,
                              mode=0o640, gid=policy_file_policy.group_gid)
        second = _fresh_gates(database_url, systemd_runner)
        _verify_gate_database_target(database_target, second)
        if policy_bytes != second["policy_bytes"]:
            raise BackupError("policy_changed")
        _verify_source_config(ENV_PATH, env_bytes, env_identity, env_chain,
                              mode=0o600, gid=env_gid)
        _verify_source_config(POLICY_PATH, policy_bytes, policy_identity, policy_chain,
                              mode=0o640, gid=policy_file_policy.group_gid)
        if (first["history"] is not None and first["history"] != second["history"]):
            raise BackupError("database_history_changed")
        if first["policy_sha256"] != second["policy_sha256"]:
            raise BackupError("policy_changed")
        _revalidate_root(root_fds, root_ids)
        _check_root(root_fd)
        if _available_bytes(root_fd) < _required_bytes(database_url, env_bytes, policy_bytes):
            raise BackupError("backup_capacity_unavailable")
        # Keep the final gate snapshot adjacent to the first artifact mutation.
        final_gates = _fresh_gates(database_url, systemd_runner)
        _verify_gate_database_target(database_target, final_gates)
        if final_gates["policy_bytes"] != policy_bytes:
            raise BackupError("policy_changed")
        if (second["history"] is not None
                and second["history"] != final_gates["history"]):
            raise BackupError("database_history_changed")
        _verify_source_config(ENV_PATH, env_bytes, env_identity, env_chain,
                              mode=0o600, gid=env_gid)
        _verify_source_config(POLICY_PATH, policy_bytes, policy_identity, policy_chain,
                              mode=0o640, gid=policy_file_policy.group_gid)
        _verify_database_target(database_target)
        _revalidate_root(root_fds, root_ids)
        _check_root(root_fd)
        planned_intent["creation"] = "attempted"
        try:
            os.mkdir(child_name, CHILD_MODE, dir_fd=root_fd)
            creation_state = "created"
            planned_intent["creation"] = "created"
        except FileExistsError:
            raise BackupError("backup_collision", recovery_path=recovery,
                              creation_state="collision") from None
        except Exception:
            raise BackupError("backup_create_failed", recovery_path=recovery,
                              creation_state="unknown") from None
        try:
            child_fd = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=root_fd)
        except Exception:
            creation_state = "unknown"
            raise BackupError("backup_child_unavailable") from None
        created = os.fstat(child_fd)
        named = os.stat(child_name, dir_fd=root_fd, follow_symlinks=False)
        _require_created_by_process(created, "backup_child_owner_invalid")
        if (_inode(created) != _inode(named) or not stat.S_ISDIR(created.st_mode)
                or stat.S_IMODE(created.st_mode) != CHILD_MODE):
            raise BackupError("backup_child_invalid")
        _chown_new(child_fd, 0, 0)
        os.fchmod(child_fd, CHILD_MODE)
        _check_child(root_fd, child_fd, child_name)
        _validate_child_path(root_fds, root_ids, root_fd, child_fd, child_name)
        os.fsync(root_fd)
        attempted.add("intent.json")
        artifact_identities["intent.json"] = _write_new_at(
            root_fds, root_ids, root_fd, child_fd, child_name,
            "intent.json", (json.dumps(planned_intent, sort_keys=True) + "\n").encode()
        )
        completed.add("intent.json")
        _sync_child(root_fds, root_ids, root_fd, child_fd, child_name)

        attempted.add("role-radar.env")
        artifact_identities["role-radar.env"] = _write_new_at(
            root_fds, root_ids, root_fd, child_fd, child_name, "role-radar.env", env_bytes
        )
        completed.add("role-radar.env")
        attempted.add("discovery-policy.toml")
        artifact_identities["discovery-policy.toml"] = _write_new_at(
            root_fds, root_ids, root_fd, child_fd, child_name,
            "discovery-policy.toml", policy_bytes
        )
        completed.add("discovery-policy.toml")

        attempted.add("role-radar.db")
        db_fd, db_identity = _create_empty_at(root_fds, root_ids, root_fd, child_fd,
                                              child_name, "role-radar.db")
        artifact_identities["role-radar.db"] = db_identity
        history = _backup_database(database_url, root_fds, root_ids, root_fd,
                                   child_fd, child_name, db_fd, db_identity,
                                   final_gates["history"], database_target)
        completed.add("role-radar.db")
        attempted.add("history.json")
        artifact_identities["history.json"] = _write_new_at(
            root_fds, root_ids, root_fd, child_fd, child_name,
            "history.json", (json.dumps(history, sort_keys=True) + "\n").encode()
        )
        completed.add("history.json")
        proof = _source_proof(database_target, env_identity, env_chain,
                              policy_identity, policy_chain, child_fd)
        attempted.add("source-proof.json")
        artifact_identities["source-proof.json"] = _write_new_at(
            root_fds, root_ids, root_fd, child_fd, child_name,
            "source-proof.json", (json.dumps(proof, sort_keys=True) + "\n").encode()
        )
        completed.add("source-proof.json")
        _sync_child(root_fds, root_ids, root_fd, child_fd, child_name)

        _verify_source_config(ENV_PATH, env_bytes, env_identity, env_chain,
                              mode=0o600, gid=env_gid)
        _verify_source_config(POLICY_PATH, policy_bytes, policy_identity, policy_chain,
                              mode=0o640, gid=policy_file_policy.group_gid)
        _verify_database_target(database_target)
        final_gates = _fresh_gates(database_url, systemd_runner)
        _verify_gate_database_target(database_target, final_gates)
        if final_gates["policy_bytes"] != policy_bytes:
            raise BackupError("policy_changed")
        if (final_gates["history"] is not None and final_gates["history"] != history):
            raise BackupError("database_history_changed")
        _verify_source_config(ENV_PATH, env_bytes, env_identity, env_chain,
                              mode=0o600, gid=env_gid)
        _verify_source_config(POLICY_PATH, policy_bytes, policy_identity, policy_chain,
                              mode=0o640, gid=policy_file_policy.group_gid)
        _verify_database_target(database_target)
        counts = {key: len(history[key]) for key in ("runs", "batches", "items")}
        result = {"schema_version": 1, "state": "created", "recovery_path": recovery,
                  "database": "created", "environment": "created", "policy": "created",
                  "history": "created", "record_counts": counts}
        attempted.add("result.json")
        artifact_identities["result.json"] = _write_new_at(
            root_fds, root_ids, root_fd, child_fd, child_name,
            "result.json", (json.dumps(result, sort_keys=True) + "\n").encode()
        )
        completed.add("result.json")
        _sync_child(root_fds, root_ids, root_fd, child_fd, child_name)
        _verify_artifacts(root_fds, root_ids, root_fd, child_fd, child_name,
                          artifact_identities)
        _revalidate_root(root_fds, root_ids)
        _check_root(root_fd)
        return Path(recovery)
    except BackupError as exc:
        exc.recovery_path = exc.recovery_path or recovery
        exc.creation_state = exc.creation_state or creation_state
        if child_fd is not None and creation_state == "created":
            states = {
                "intent": _artifact_state("intent.json", attempted, completed),
                "environment": _artifact_state("role-radar.env", attempted, completed),
                "policy": _artifact_state("discovery-policy.toml", attempted, completed),
                "database": _artifact_state("role-radar.db", attempted, completed),
                "history": _artifact_state("history.json", attempted, completed),
                "source_proof": _artifact_state("source-proof.json", attempted, completed),
                "result": _artifact_state("result.json", attempted, completed),
                "creation": "created",
            }
            _write_partial(root_fds, root_ids, root_fd, child_fd, child_name,
                           recovery, states, str(exc))
        raise
    except Exception:
        failure = BackupError("backup_failed", recovery_path=recovery,
                              creation_state=creation_state)
        if child_fd is not None and creation_state == "created":
            states = {
                "intent": _artifact_state("intent.json", attempted, completed),
                "environment": _artifact_state("role-radar.env", attempted, completed),
                "policy": _artifact_state("discovery-policy.toml", attempted, completed),
                "database": _artifact_state("role-radar.db", attempted, completed),
                "history": _artifact_state("history.json", attempted, completed),
                "source_proof": _artifact_state("source-proof.json", attempted, completed),
                "result": _artifact_state("result.json", attempted, completed),
                "creation": "created",
            }
            _write_partial(root_fds, root_ids, root_fd, child_fd, child_name,
                           recovery, states, str(failure))
        raise failure from None
    finally:
        if child_fd is not None:
            os.close(child_fd)
        _close_all(root_fds)
        _close_database_target(database_target)


def create_backup(database_url: str = DB_URL, *, systemd_runner=None) -> Path:
    return _create_backup(database_url, systemd_runner=systemd_runner)


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise BackupError("arguments_invalid")


def main(argv=None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if sum(x == "--database-url" or x.startswith("--database-url=") for x in tokens) > 1:
        print("PROTECTED_BACKUP: FAIL (arguments_invalid)", file=sys.stderr)
        return 1
    parser = _Parser(
        description="Create a protected canary backup only; does not create or start a run.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--database-url", default=DB_URL,
        help="SQLite file URL; relative paths resolve from current working directory",
    )
    try:
        args = parser.parse_args(argv)
        try:
            database._database_url_path(args.database_url)
        except Exception:
            raise BackupError("database_target_invalid") from None
        recovery = create_backup(args.database_url)
    except SystemExit:
        raise
    except BackupError as exc:
        location = f"; recovery={exc.recovery_path}" if exc.recovery_path else ""
        creation = f"; creation={exc.creation_state}" if exc.creation_state else ""
        print(f"PROTECTED_BACKUP: FAIL ({exc}{creation}{location})", file=sys.stderr)
        return 1
    except Exception:
        print("PROTECTED_BACKUP: FAIL (backup_failed)", file=sys.stderr)
        return 1
    print(f"PROTECTED_BACKUP: PASS (backup complete; recovery={recovery})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
