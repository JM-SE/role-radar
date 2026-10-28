#!/usr/bin/env python3
"""Create exactly one canary run from one verified protected backup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager, suppress
from pathlib import Path

from scripts import bounded_canary_artifacts as artifacts
from scripts import bounded_canary_backup as backup
from scripts import bounded_canary_database as database

APP_ROOT = Path("/opt/role-radar")
BACKUP_ROOT = backup.BACKUP_ROOT
DATABASE_PATH = APP_ROOT / "data" / "role-radar.db"
RUNUSER = "/usr/sbin/runuser"
CHILD_TIMEOUT = 40
MAX_CHILD_OUTPUT = 4096
BACKUP_NAME = re.compile(r"canary-[0-9a-f]{32}\Z")


class CreationError(Exception):
    def __init__(self, code: str, *, recovery: str | None = None):
        super().__init__(code)
        self.code = code
        self.recovery = recovery


def _json(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def _read_at(child_fd: int, name: str, *, maximum: int = 8_000_000, hash_only: bool = False):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     dir_fd=child_fd)
        before = os.fstat(fd)
        named = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        backup._require_owner(before, 0, 0, "backup_artifact_invalid")
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1 or backup._identity(before) != backup._identity(named)
                or before.st_size > maximum):
            raise CreationError("backup_artifact_invalid")
        chunks = bytearray()
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise CreationError("backup_artifact_invalid")
            digest.update(block)
            if not hash_only:
                chunks.extend(block)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        if (backup._identity(before) != backup._identity(after)
                or backup._identity(after) != backup._identity(named_after)):
            raise CreationError("backup_changed")
        return (None if hash_only else bytes(chunks)), backup._identity(after), digest.hexdigest()
    except CreationError:
        raise
    except Exception:
        raise CreationError("backup_artifact_invalid") from None
    finally:
        if fd is not None:
            os.close(fd)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_retained_backup(child_fd, identities, digests):
    for name, expected_identity in identities.items():
        maximum = (2_000_000_000 if name == "role-radar.db"
                   else 2_000_000 if name.endswith((".toml", ".env")) else 8_000_000)
        _data, identity, digest = _read_at(
            child_fd, name, maximum=maximum, hash_only=True
        )
        if identity != expected_identity or digest != digests[name]:
            raise CreationError("backup_changed")


def _open_backup_files(path: Path, *, reject_attempt: bool):
    if not path.is_absolute() or path.parent != BACKUP_ROOT or not BACKUP_NAME.fullmatch(path.name):
        raise CreationError("backup_path_invalid")
    root_fds = root_ids = child_fd = None
    try:
        root_fds, root_ids = backup._open_chain(BACKUP_ROOT)
        root_fd = root_fds[-1]
        backup._check_root(root_fd)
        child_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        backup._check_child(root_fd, child_fd, path.name)
        names = set(os.listdir(child_fd))
        required = {
            "discovery-policy.toml", "history.json", "intent.json", "result.json",
            "role-radar.db", "role-radar.env", "source-proof.json",
        }
        if (names - required - {"create-attempt.json", "creation-outcome.json"}
                or not required <= names):
            raise CreationError("backup_incomplete", recovery=str(path))
        if reject_attempt and "create-attempt.json" in names:
            raise CreationError("creation_attempt_exists", recovery=str(path))
        info = os.fstat(child_fd)
        backup_identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                           stat.S_IMODE(info.st_mode), info.st_nlink)
        files = {}
        identities = {}
        digests = {}
        for name in ("source-proof.json", "result.json", "history.json", "role-radar.db",
                     "role-radar.env", "discovery-policy.toml", "intent.json"):
            data, identity, digest = _read_at(
                child_fd, name,
                maximum=(2_000_000_000 if name == "role-radar.db"
                         else 2_000_000 if name.endswith((".toml", ".env")) else 8_000_000),
                hash_only=name == "role-radar.db",
            )
            files[name] = data
            identities[name] = identity
            digests[name] = digest
        proof = _json(files["source-proof.json"])
        result = _json(files["result.json"])
        if (type(proof) is not dict or type(proof.get("schema_version")) is not int
                or proof["schema_version"] != backup.SOURCE_PROOF_VERSION):
            raise CreationError("backup_source_proof_invalid", recovery=str(path))
        history = _json(files["history.json"])
        if type(history) is not dict or set(history) != {"runs", "batches", "items"}:
            raise CreationError("backup_history_invalid", recovery=str(path))
        expected_counts = {name: len(history[name]) for name in ("runs", "batches", "items")}
        counts = result.get("record_counts") if type(result) is dict else None
        if (type(result) is not dict or type(result.get("schema_version")) is not int
                or result["schema_version"] != 1 or type(counts) is not dict
                or set(counts) != set(expected_counts)
                or any(type(counts[name]) is not int or counts[name] < 0
                       for name in expected_counts)):
            raise CreationError("backup_incomplete", recovery=str(path))
        expected_result = {
            "schema_version": 1, "state": "created", "recovery_path": str(path),
            "database": "created", "environment": "created", "policy": "created",
            "history": "created", "record_counts": expected_counts,
        }
        if result != expected_result:
            raise CreationError("backup_incomplete", recovery=str(path))
        intent = _json(files["intent.json"])
        if (type(intent) is not dict or type(intent.get("schema_version")) is not int
                or intent.get("schema_version") != 1 or intent.get("state") != "attempted"
                or intent.get("creation") != "created" or intent.get("recovery_path") != str(path)):
            raise CreationError("backup_incomplete", recovery=str(path))
        _validate_proof(proof, files, identities, digests)
        return (root_fds, root_ids, root_fd, child_fd, backup_identity,
                files, identities, digests, proof)
    except Exception:
        if child_fd is not None:
            with suppress(OSError):
                os.close(child_fd)
        if root_fds:
            backup._close_all(root_fds)
        raise


def _open_backup(path: Path):
    return _open_backup_files(path, reject_attempt=True)


@contextmanager
def _open_creation_evidence(path: Path):
    """Yield private, descriptor-anchored evidence for one successful create."""
    try:
        opened = _open_backup_files(path, reject_attempt=False)
    except CreationError:
        raise
    except Exception:
        raise CreationError("creation_evidence_invalid") from None
    (root_fds, root_ids, root_fd, child_fd, backup_identity, files,
     identities, digests, proof) = opened
    try:
        try:
            attempt_data, attempt_identity, attempt_digest = _read_at(
                child_fd, "create-attempt.json"
            )
            outcome_data, outcome_identity, outcome_digest = _read_at(
                child_fd, "creation-outcome.json"
            )
            attempt, outcome = _json(attempt_data), _json(outcome_data)
        except Exception:
            raise CreationError("creation_evidence_invalid") from None
        if (type(attempt) is not dict
                or set(attempt) != {
                    "schema_version", "state", "backup", "backup_identity", "profile_id"
                }
                or type(attempt.get("schema_version")) is not int
                or attempt["schema_version"] != 1 or attempt.get("state") != "attempted"
                or attempt.get("backup") != str(path)
                or not _int_list(attempt.get("backup_identity"), len(backup_identity))
                or attempt["backup_identity"] != list(backup_identity)
                or type(attempt.get("profile_id")) is not str
                or type(outcome) is not dict
                or set(outcome) != {"schema_version", "state", "run_id", "profile_id"}
                or type(outcome.get("schema_version")) is not int
                or outcome["schema_version"] != 1 or outcome.get("state") != "created"
                or outcome.get("profile_id") != attempt.get("profile_id")):
            raise CreationError("creation_evidence_invalid")
        for value in (attempt["profile_id"], outcome.get("run_id")):
            if type(value) is not str or str(uuid.UUID(value)) != value:
                raise CreationError("creation_evidence_invalid")
        _validate_backup_anchors(
            root_fds, root_ids, root_fd, child_fd, backup_identity, path.name
        )
        _validate_retained_backup(child_fd, identities, digests)
        for name, identity, digest in (
            ("create-attempt.json", attempt_identity, attempt_digest),
            ("creation-outcome.json", outcome_identity, outcome_digest),
        ):
            _data, current_identity, current_digest = _read_at(
                child_fd, name, hash_only=True
            )
            if current_identity != identity or current_digest != digest:
                raise CreationError("creation_evidence_invalid")
        yield {
            "backup_path": path, "backup_identity": backup_identity,
            "profile_id": attempt["profile_id"], "run_id": outcome["run_id"],
            "history": _json(files["history.json"]), "source_proof": proof,
            "artifact_identities": {**identities,
                                    "create-attempt.json": attempt_identity,
                                    "creation-outcome.json": outcome_identity},
            "artifact_digests": {**digests, "create-attempt.json": attempt_digest,
                                  "creation-outcome.json": outcome_digest},
            "root_fds": root_fds, "root_ids": root_ids, "root_fd": root_fd,
            "child_fd": child_fd,
        }
    except CreationError:
        raise
    except Exception:
        raise CreationError("creation_evidence_invalid") from None
    finally:
        try:
            os.close(child_fd)
        finally:
            backup._close_all(root_fds)


def _int_list(value, length: int) -> bool:
    return (type(value) is list and len(value) == length
            and all(type(item) is int and item >= 0 for item in value))


def _validate_proof(proof, files, identities, digests) -> None:
    if set(proof) != {"schema_version", "source", "backup"}:
        raise CreationError("backup_source_proof_invalid")
    source, copied = proof["source"], proof["backup"]
    if type(source) is not dict or set(source) != {"database", "environment", "policy"}:
        raise CreationError("backup_source_proof_invalid")
    if type(copied) is not dict or set(copied) != {
        "database_sha256", "database_identity", "history_sha256", "environment_sha256",
        "policy_sha256"
    }:
        raise CreationError("backup_source_proof_invalid")
    paths = {
        "database": str(DATABASE_PATH),
        "environment": str(backup.ENV_PATH),
        "policy": str(backup.POLICY_PATH),
    }
    for name, path in paths.items():
        item = source[name]
        expected_fields = (
            {"path", "identity", "ownership", "parent_identities"}
            if name == "database"
            else {"path", "identity", "parent_identities", "sha256"}
        )
        if (type(item) is not dict or set(item) != expected_fields or item.get("path") != path
                or not _int_list(item.get("identity"), 7 if name == "database" else 9)
                or type(item.get("parent_identities")) is not list
                or not item["parent_identities"]
                or any(not _int_list(pair, 2) for pair in item["parent_identities"])):
            raise CreationError("backup_source_proof_invalid")
        if name == "database" and not _int_list(item.get("ownership"), 3):
            raise CreationError("backup_source_proof_invalid")
        if name != "database" and (
            type(item.get("sha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        ):
            raise CreationError("backup_source_proof_invalid")
    if (not _int_list(copied.get("database_identity"), 9)
            or copied["database_identity"] != list(identities["role-radar.db"])
            or copied.get("database_sha256") != digests["role-radar.db"]
            or copied.get("history_sha256") != _sha(files["history.json"])
            or copied.get("environment_sha256") != _sha(files["role-radar.env"])
            or copied.get("policy_sha256") != _sha(files["discovery-policy.toml"])):
        raise CreationError("backup_source_proof_invalid")
    for name, filename in (("environment", "role-radar.env"), ("policy", "discovery-policy.toml")):
        if source[name]["sha256"] != _sha(files[filename]):
            raise CreationError("backup_source_proof_invalid")
    try:
        history = _json(files["history.json"])
        if type(history) is not dict or set(history) != {"runs", "batches", "items"}:
            raise ValueError
    except Exception:
        raise CreationError("backup_history_invalid") from None


def _current_source(proof):
    database_source = proof["source"]["database"]
    url = "sqlite:////" + str(DATABASE_PATH).lstrip("/")
    target = backup._capture_database_target(url)
    try:
        info = os.fstat(target["source_fd"])
        ownership = [info.st_uid, info.st_gid, info.st_nlink]
        if (str(target["path"]) != database_source["path"]
                or list(target["identity"]) != database_source["identity"]
                or ownership != database_source["ownership"]
                or [list(item) for item in target["parent_ids"]]
                != database_source["parent_identities"]):
            raise CreationError("source_database_changed")
    finally:
        backup._close_database_target(target)
    for name, path, mode, gid in (
        ("environment", backup.ENV_PATH, 0o600, 0),
        ("policy", backup.POLICY_PATH, 0o640,
         backup.binding.production_discovery_policy_file_policy().group_gid),
    ):
        item = proof["source"][name]
        data, identity, chain = backup._fixed_file(path, mode=mode, gid=gid)
        if (str(path) != item["path"] or list(identity) != item["identity"]
                or [list(pair) for pair in chain] != item["parent_identities"]
                or _sha(data) != item["sha256"]):
            raise CreationError("source_config_changed")
    return url


def _fresh_gates(database_url: str):
    return backup._fresh_gates(database_url)


def _json_value(value):
    return json.loads(json.dumps(value, sort_keys=True))


def _run_metadata(connection):
    return {row[0]: tuple(row[1:]) for row in database._rows(
        connection,
        "SELECT id, canary_budget_json, canary_checkpoint_json, notification_mode, discovery_mode "
        "FROM job_search_runs ORDER BY id"
    )}


def _create_attempt(root_fds, root_ids, root_fd, child_fd, backup_identity, recovery, profile_id):
    if "create-attempt.json" in os.listdir(child_fd):
        raise CreationError("creation_attempt_exists", recovery=recovery)
    record = {"schema_version": 1, "state": "attempted", "backup": recovery,
              "backup_identity": list(backup_identity), "profile_id": profile_id}
    data = (json.dumps(record, sort_keys=True) + "\n").encode()

    def validate():
        _validate_backup_anchors(
            root_fds, root_ids, root_fd, child_fd, backup_identity, Path(recovery).name
        )
    try:
        artifacts.write_new_at(
            child_fd, "create-attempt.json", data, uid=0, gid=0, mode=0o600,
            chown=backup._chown_new,
            require_owner=lambda info, uid, gid: backup._require_owner(
                info, uid, gid, "artifact_owner_invalid"),
            validate_parent=validate,
        )
        os.fsync(child_fd)
        os.fsync(root_fd)
    except Exception:
        raise CreationError("attempt_intent_uncertain", recovery=recovery) from None


def _validate_backup_anchors(root_fds, root_ids, root_fd, child_fd, identity, child_name):
    backup._revalidate_root(root_fds, root_ids)
    backup._check_root(root_fd)
    info = os.fstat(child_fd)
    named = os.stat(child_name, dir_fd=root_fd, follow_symlinks=False)
    def stable(item):
        return (item.st_dev, item.st_ino, item.st_uid, item.st_gid,
                stat.S_IMODE(item.st_mode), item.st_nlink)
    if (stable(info) != identity or stable(named) != identity
            or not stat.S_ISDIR(info.st_mode)):
        raise CreationError("backup_changed")


def _write_outcome(child_fd, root_fd, root_fds, root_ids, backup_identity, recovery, value):
    data = (json.dumps(value, sort_keys=True) + "\n").encode()

    def validate():
        _validate_backup_anchors(
            root_fds, root_ids, root_fd, child_fd, backup_identity, Path(recovery).name
        )
    try:
        artifacts.write_new_at(
            child_fd, "creation-outcome.json", data, uid=0, gid=0, mode=0o600,
            chown=backup._chown_new,
            require_owner=lambda info, uid, gid: backup._require_owner(
                info, uid, gid, "artifact_owner_invalid"),
            validate_parent=validate,
        )
        os.fsync(child_fd)
        os.fsync(root_fd)
    except Exception:
        raise CreationError("creation_outcome_unavailable", recovery=recovery) from None


def _pre_history(connection):
    return database.snapshot_history(connection), _run_metadata(connection)


def _post_create(connection, before_history, before_metadata, run_id, profile_id):
    snapshot = database.snapshot_history(connection)
    metadata = _run_metadata(connection)
    old_ids = set(before_metadata)
    added = set(metadata) - old_ids
    previous = {key: value for key, value in metadata.items() if key in old_ids}
    if added != {run_id} or previous != before_metadata:
        raise CreationError("created_run_history_invalid")
    old_history = before_history["runs"]
    new_history = [row for row in snapshot["runs"] if row["id"] not in old_ids]
    if len(new_history) != 1 or new_history[0]["id"] != run_id:
        raise CreationError("created_run_history_invalid")
    new = new_history[0]
    if (new["status"] != "pending" or new["profile_id"] != profile_id
            or new["claimed_by"] is not None or new["lease_expires_at"] is not None
            or new["started_at"] is not None or new["completed_at"] is not None):
        raise CreationError("created_run_invalid")
    if [row for row in snapshot["runs"] if row["id"] in old_ids] != list(old_history):
        raise CreationError("created_run_history_invalid")
    if (snapshot["batches"] != before_history["batches"]
            or snapshot["items"] != before_history["items"]):
        raise CreationError("created_outbox_changed")
    budget_raw, checkpoint_raw, notification_mode, discovery_mode = metadata[run_id]
    budget = _json(budget_raw.encode() if type(budget_raw) is str else budget_raw)
    checkpoint = _json(checkpoint_raw.encode() if type(checkpoint_raw) is str else checkpoint_raw)
    from role_radar.domain.enums import DiscoveryMode, NotificationMode
    from role_radar.execution_budget import CANARY_BUDGET, validate_canary_checkpoint
    if (type(budget) is not dict or budget != CANARY_BUDGET
            or type(checkpoint) is not dict
            or checkpoint != {"version": 1, "stage": "discovery", "cursor": 0,
                              "counts": {}, "reservations": [], "logical_reservations": []}
            or validate_canary_checkpoint(checkpoint) != ("discovery", 0)
            or notification_mode != NotificationMode.MATCH_ALERTS.value
            or discovery_mode != DiscoveryMode.SCHEDULED_DUE.value):
        raise CreationError("created_run_invalid")


def _dispatch(database_url: str, profile_id: str):
    env = {
        "PATH": f"{APP_ROOT}/.venv/bin:/usr/bin", "LANG": "C",
        "HOME": str(APP_ROOT), "ROLE_RADAR_DATABASE_URL": database_url,
    }
    command = [RUNUSER, "-u", "role-radar", "--", "/usr/bin/env", "-i",
               *(f"{key}={value}" for key, value in env.items()), "role-radar",
               "run", "create", "--canary", "--profile-id", profile_id]
    try:
        return subprocess.run(
            command, cwd=APP_ROOT, env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"},
                              capture_output=True, text=True, timeout=CHILD_TIMEOUT,
                              check=False, shell=False)
    except Exception:
        return None


def _execute(path: Path) -> None:
    root_fds = root_ids = child_fd = live = None
    try:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise CreationError("operator_privilege_required")
        (root_fds, root_ids, root_fd, child_fd, backup_identity,
         files, identities, digests, proof) = _open_backup(path)
        if "create-attempt.json" in os.listdir(child_fd):
            raise CreationError("creation_attempt_exists", recovery=str(path))
        db_url = _current_source(proof)
        # T2a checked the DB/history pair; its result and digests bind the retained files.
        history = _json(files["history.json"])
        gates = _fresh_gates(db_url)
        if (gates["database_target"][0] != Path(proof["source"]["database"]["path"])
                or list(gates["database_target"][1]) != proof["source"]["database"]["identity"]
                or _json_value(gates["history"]) != history
                or gates["policy_bytes"] != files["discovery-policy.toml"]
                or gates.get("bound_profile_id") is None):
            raise CreationError("fresh_gate_mismatch", recovery=str(path))
        profile_id = gates["bound_profile_id"]
        try:
            if str(uuid.UUID(profile_id)) != profile_id:
                raise ValueError
        except Exception:
            raise CreationError("profile_binding_invalid", recovery=str(path)) from None
        live = database._connect_database(db_url)
        before_history, before_metadata = _pre_history(live)
        live.execute("ROLLBACK")
        if _json_value(before_history) != history:
            raise CreationError("database_history_changed", recovery=str(path))
        # Repeat source identity checks immediately before the durable exclusive intent.
        _current_source(proof)
        _validate_backup_anchors(root_fds, root_ids, root_fd, child_fd, backup_identity, path.name)
        _create_attempt(
            root_fds, root_ids, root_fd, child_fd, backup_identity, str(path), profile_id
        )
        try:
            _validate_backup_anchors(
                root_fds, root_ids, root_fd, child_fd, backup_identity, path.name
            )
            _current_source(proof)
            _validate_retained_backup(child_fd, identities, digests)
        except Exception:
            _write_outcome(
                child_fd, root_fd, root_fds, root_ids, backup_identity, str(path),
                {"schema_version": 1, "state": "uncertain",
                 "code": "pre_dispatch_recheck_failed"},
            )
            raise CreationError("creation_uncertain", recovery=str(path)) from None
        output = _dispatch(db_url, profile_id)
        run_id = None
        try:
            if (output is None or output.returncode != 0 or type(output.stdout) is not str
                    or type(output.stderr) is not str or len(output.stdout) > MAX_CHILD_OUTPUT
                    or len(output.stderr) > MAX_CHILD_OUTPUT or output.stderr != ""):
                raise ValueError
            payload = _json(output.stdout.encode())
            if (type(payload) is not dict or set(payload) != {"id", "status"}
                    or payload["status"] != "pending"):
                raise ValueError
            run_id = payload["id"]
            if type(run_id) is not str or str(uuid.UUID(run_id)) != run_id:
                raise ValueError
            live.execute("BEGIN")
            _post_create(live, before_history, before_metadata, run_id, profile_id)
            _current_source_after_dispatch(proof)
            _validate_retained_backup(child_fd, identities, digests)
        except Exception:
            _write_outcome(child_fd, root_fd, root_fds, root_ids, backup_identity, str(path),
                           {"schema_version": 1, "state": "uncertain",
                            "code": "child_result_invalid"})
            raise CreationError("creation_uncertain", recovery=str(path)) from None
        _write_outcome(child_fd, root_fd, root_fds, root_ids, backup_identity, str(path),
                       {"schema_version": 1, "state": "created", "run_id": run_id,
                        "profile_id": profile_id})
    finally:
        if live is not None:
            live.close()
        if child_fd is not None:
            os.close(child_fd)
        if root_fds:
            backup._close_all(root_fds)


def _current_source_after_dispatch(proof):
    # Only SQLite payload, size and timestamps may change after creation.
    source = proof["source"]["database"]
    original_identity = source["identity"]
    target = backup._capture_database_target("sqlite:////" + str(DATABASE_PATH).lstrip("/"))
    try:
        info = os.fstat(target["source_fd"])
        ownership = [info.st_uid, info.st_gid, info.st_nlink]
        if (str(target["path"]) != source["path"]
                or target["identity"][:3] != tuple(original_identity[:3])
                or target["identity"][6] != original_identity[6]
                or ownership != source["ownership"]
                or [list(pair) for pair in target["parent_ids"]] != source["parent_identities"]):
            raise CreationError("source_database_changed")
    finally:
        backup._close_database_target(target)
    for name, path, mode, gid in (
        ("environment", backup.ENV_PATH, 0o600, 0),
        ("policy", backup.POLICY_PATH, 0o640,
         backup.binding.production_discovery_policy_file_policy().group_gid),
    ):
        item = proof["source"][name]
        data, identity, chain = backup._fixed_file(path, mode=mode, gid=gid)
        if (list(identity) != item["identity"]
                or [list(pair) for pair in chain] != item["parent_identities"]
                or _sha(data) != item["sha256"]):
            raise CreationError("source_config_changed")


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise CreationError("arguments_invalid")


def main(argv=None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if sum(token == "--backup" or token.startswith("--backup=") for token in tokens) > 1:
        print("CANARY_CREATION: FAIL (arguments_invalid)", file=sys.stderr)
        return 1
    parser = _Parser(
        description="Create one canary from an existing verified backup; never start a worker.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--backup", required=True, help="protected direct child under the fixed backup root"
    )
    try:
        args = parser.parse_args(argv)
        path = Path(args.backup)
        if not path.is_absolute() or str(path) != args.backup:
            raise CreationError("arguments_invalid")
        _execute(path)
    except SystemExit:
        raise
    except CreationError as exc:
        location = exc.recovery or (
            str(path) if "path" in locals() and path.parent == BACKUP_ROOT
            and BACKUP_NAME.fullmatch(path.name) else None
        )
        suffix = f"; recovery={location}" if location else ""
        print(f"CANARY_CREATION: FAIL ({exc.code}{suffix})", file=sys.stderr)
        return 1
    except Exception:
        print("CANARY_CREATION: FAIL (creation_failed)", file=sys.stderr)
        return 1
    print(f"CANARY_CREATION: PASS (recovery={path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
