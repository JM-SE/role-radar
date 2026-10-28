#!/usr/bin/env python3
"""Offline-reconstructed protected Telegram provider prepare/restore transaction."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from scripts import bounded_canary_artifacts as artifacts
from scripts import bounded_canary_backup as backup
from scripts import bounded_canary_create as creation
from scripts import bounded_canary_database as database

_PROVIDER = b"ROLE_RADAR_TELEGRAM_PROVIDER"
_ASSIGNMENT = re.compile(
    rb"[ \t]*([A-Za-z_][A-Za-z0-9_]*)=([ \t]*)([A-Za-z0-9_./:@%+=,-]*)([ \t]*)"
)
RECEIPT_NAME = "provider-intent.json"
OUTCOME_NAME = "provider-outcome.json"
RESTORE_NAME = "provider-restore-intent.json"
RESTORE_OUTCOME_NAME = "provider-restore-outcome.json"
RECEIPT_VERSION = 1


class ProviderBytesError(Exception):
    """Fixed, privacy-safe rejection for unsupported provider-file bytes."""

    code = "provider_config_invalid"

    def __init__(self):
        super().__init__(self.code)


class ProviderError(Exception):
    def __init__(self, code: str, recovery: str | None = None):
        super().__init__(code)
        self.code = code
        self.recovery = recovery


def prepare_telegram_provider_bytes(original: bytes) -> bytes:
    """Replace exactly one canonical disabled selector, preserving every other byte."""
    if type(original) is not bytes:
        raise ProviderBytesError()
    output = bytearray()
    count = 0
    offset = 0
    while offset < len(original):
        newline = original.find(b"\n", offset)
        end = len(original) if newline < 0 else newline
        line_end = end
        ending = b"" if newline < 0 else b"\n"
        if newline >= 0 and line_end > offset and original[line_end - 1:line_end] == b"\r":
            line_end -= 1
            ending = b"\r\n"
        line = original[offset:line_end]
        if b"\r" in line:
            raise ProviderBytesError()
        stripped = line.strip(b" \t")
        if stripped and not stripped.startswith(b"#"):
            match = _ASSIGNMENT.fullmatch(line)
            if match is None:
                raise ProviderBytesError()
            key, _padding, value, _trailing = match.groups()
            if key.upper() == _PROVIDER and key != _PROVIDER:
                raise ProviderBytesError()
            if key == _PROVIDER:
                count += 1
                if count != 1 or value != b"disabled":
                    raise ProviderBytesError()
                start = match.start(3)
                line = line[:start] + b"http" + line[start + len(value):]
        output.extend(line)
        output.extend(ending)
        if newline < 0:
            break
        offset = newline + 1
    if count != 1:
        raise ProviderBytesError()
    return bytes(output)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_identity(value) -> bool:
    return (type(value) is list and len(value) == 9
            and all(type(item) is int and item >= 0 for item in value))


def _valid_digest(value) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _valid_canary_budget(value) -> bool:
    from role_radar.execution_budget import CANARY_BUDGET

    limits = value.get("limits") if type(value) is dict else None
    return (type(value) is dict and set(value) == {"version", "limits"}
            and type(value["version"]) is int and value["version"] == 1
            and type(limits) is dict and set(limits) == set(CANARY_BUDGET["limits"])
            and all(type(limit) is int for limit in limits.values())
            and value == CANARY_BUDGET)


def _identity(info) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _json(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def _read_private(child_fd: int, name: str, *, maximum: int = 64_000):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     dir_fd=child_fd)
        before = os.fstat(fd)
        named = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        backup._require_owner(before, 0, 0, "provider_evidence_invalid")
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1 or _identity(before) != _identity(named)
                or before.st_size > maximum):
            raise ProviderError("provider_evidence_invalid")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(8192, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=child_fd, follow_symlinks=False)
        if len(chunks) > maximum or _identity(before) != _identity(after) \
                or _identity(after) != _identity(named_after):
            raise ProviderError("provider_evidence_invalid")
        return bytes(chunks), _identity(after)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("provider_evidence_invalid") from None
    finally:
        if fd is not None:
            os.close(fd)


def _validate_creation(path: Path):
    try:
        with creation._open_creation_evidence(path) as evidence:
            return {key: value for key, value in evidence.items()}
    except creation.CreationError:
        raise ProviderError("creation_evidence_invalid", str(path)) from None
    except Exception:
        raise ProviderError("creation_evidence_invalid", str(path)) from None


def _current_environment(proof, *, expected_identity=None, expected_sha256=None):
    item = proof["source"]["environment"]
    data, identity, parents = backup._fixed_file(
        backup.ENV_PATH, mode=0o600, gid=0
    )
    if (item["path"] != str(backup.ENV_PATH)
            or [list(pair) for pair in parents] != item["parent_identities"]):
        raise ProviderError("source_config_changed")
    if expected_identity is None:
        if list(identity) != item["identity"] or _sha(data) != item["sha256"]:
            raise ProviderError("source_config_changed")
    elif list(identity) != expected_identity or _sha(data) != expected_sha256:
        raise ProviderError("provider_config_changed")
    return data, identity, parents


def _validate_pending(database_url: str, evidence, gates):
    run_id, profile_id = evidence["run_id"], evidence["profile_id"]
    if gates.get("bound_profile_id") != profile_id:
        raise ProviderError("profile_binding_invalid")
    connection = None
    try:
        connection = database._connect_database(database_url)
        rows = database._rows(
            connection,
            "SELECT id, status, profile_id, started_at, completed_at, claimed_by, "
            "lease_expires_at, canary_budget_json, canary_checkpoint_json, "
            "notification_mode, discovery_mode "
            "FROM job_search_runs ORDER BY id",
        )
        matches = [row for row in rows if row[0] == run_id]
        if len(matches) != 1:
            raise ProviderError("run_state_invalid")
        row = matches[0]
        if (row[1] != "pending" or row[2] != profile_id or row[3] is not None
                or row[4] is not None or row[5] is not None or row[6] is not None):
            raise ProviderError("run_state_invalid")
        try:
            budget = creation._json(row[7].encode() if isinstance(row[7], str) else row[7])
            checkpoint = creation._json(
                row[8].encode() if isinstance(row[8], str) else row[8]
            )
            from role_radar.domain.enums import DiscoveryMode, NotificationMode
            from role_radar.execution_budget import validate_canary_checkpoint
            expected_checkpoint = {
                "version": 1, "stage": "discovery", "cursor": 0, "counts": {},
                "reservations": [], "logical_reservations": [],
            }
            if (not _valid_canary_budget(budget)
                    or type(checkpoint) is not dict
                    or validate_canary_checkpoint(checkpoint) != ("discovery", 0)
                    or checkpoint != expected_checkpoint
                    or row[9] != NotificationMode.MATCH_ALERTS.value
                    or row[10] != DiscoveryMode.SCHEDULED_DUE.value):
                raise ValueError
        except Exception:
            raise ProviderError("run_state_invalid") from None
        history = evidence.get("history")
        gate_history = gates.get("history")
        if (type(history) is not dict or type(gate_history) is not dict
                or len(rows) != len(history["runs"]) + 1):
            raise ProviderError("run_history_changed")
        current_history = database.snapshot_history(connection)
        if current_history != gate_history:
            raise ProviderError("run_history_changed")
        old_runs = [item for item in gate_history["runs"] if item["id"] != run_id]
        if (old_runs != history["runs"]
                or list(gate_history["batches"]) != history["batches"]
                or list(gate_history["items"]) != history["items"]
                or any(item[0] not in {row["id"] for row in history["runs"]}
                       and item[0] != run_id for item in rows)):
            raise ProviderError("run_history_changed")
        if gates.get("database_target") != (connection.target_path, connection.target_identity):
            raise ProviderError("database_target_changed")
        database._verify_target_stable(connection)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("run_state_unavailable") from None
    finally:
        if connection is not None:
            connection.close()


def _validate_restore_run(database_url: str, evidence):
    connection = None
    try:
        connection = database._connect_database(database_url)
        rows = tuple(connection.execute(
            "SELECT id, status, profile_id, canary_budget_json, notification_mode, "
            "discovery_mode FROM job_search_runs WHERE id=?", (evidence["run_id"],)
        ).fetchall())
        if len(rows) != 1:
            raise ProviderError("run_state_invalid")
        row = rows[0]
        from role_radar.domain.enums import DiscoveryMode, JobSearchRunStatus, NotificationMode
        budget = creation._json(row[3].encode() if isinstance(row[3], str) else row[3])
        if (row[1] not in {status.value for status in JobSearchRunStatus}
                or row[2] != evidence["profile_id"] or not _valid_canary_budget(budget)
                or row[4] != NotificationMode.MATCH_ALERTS.value
                or row[5] != DiscoveryMode.SCHEDULED_DUE.value):
            raise ProviderError("run_state_invalid")
        database._verify_target_stable(connection)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("run_state_unavailable") from None
    finally:
        if connection is not None:
            connection.close()


def _validate_original_sources(evidence):
    proof = evidence["source_proof"]["source"]
    database_source = proof["database"]
    target = None
    try:
        url = "sqlite:////" + database_source["path"].lstrip("/")
        target = backup._capture_database_target(url)
        info = os.fstat(target["source_fd"])
        if (str(target["path"]) != database_source["path"]
                or list(target["identity"][:3]) != database_source["identity"][:3]
                or target["identity"][6] != database_source["identity"][6]
                or [info.st_uid, info.st_gid, info.st_nlink] != database_source["ownership"]
                or [list(pair) for pair in target["parent_ids"]]
                != database_source["parent_identities"]):
            raise ProviderError("source_database_changed")
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("source_database_changed") from None
    finally:
        if target is not None:
            backup._close_database_target(target)
    policy = proof["policy"]
    try:
        policy_policy = backup.binding.production_discovery_policy_file_policy()
        data, identity, parents = backup._fixed_file(
            backup.POLICY_PATH, mode=0o640, gid=policy_policy.group_gid
        )
        if (str(backup.POLICY_PATH) != policy["path"]
                or list(identity) != policy["identity"]
                or [list(pair) for pair in parents] != policy["parent_identities"]
                or _sha(data) != policy["sha256"]):
            raise ProviderError("source_config_changed")
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("source_config_changed") from None


def _revalidate_creation(path: Path, evidence):
    current = _validate_creation(path)
    if (current["backup_identity"] != evidence["backup_identity"]
            or current["artifact_identities"] != evidence["artifact_identities"]
            or current["artifact_digests"] != evidence["artifact_digests"]
            or current["profile_id"] != evidence["profile_id"]
            or current["run_id"] != evidence["run_id"]
            or current["source_proof"] != evidence["source_proof"]
            or current["history"] != evidence["history"]):
        raise ProviderError("provider_evidence_changed", str(path))


def _check_evidence_child(root_fd, child_fd, path: Path, evidence):
    backup._check_child(root_fd, child_fd, path.name)
    info = os.fstat(child_fd)
    identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                stat.S_IMODE(info.st_mode), info.st_nlink)
    if identity != evidence["backup_identity"]:
        raise ProviderError("provider_evidence_changed", str(path))


def _fresh_transaction(path: Path, evidence, *, expected_environment=None,
                       operation="prepare"):
    proof = evidence["source_proof"]
    env, identity, parents = (
        _current_environment(proof) if expected_environment is None else
        _current_environment(proof, expected_identity=expected_environment[0],
                             expected_sha256=expected_environment[1])
    )
    database_url = "sqlite:////" + proof["source"]["database"]["path"].lstrip("/")
    _validate_original_sources(evidence)
    try:
        backup.provenance.verify_sources()
        if operation == "prepare":
            backup.preflight.run_gate(evidence["run_id"])
        connection = database._connect_database(database_url)
        try:
            database._validate_schema(connection)
            if database._rows(connection, "PRAGMA integrity_check") != (("ok",),):
                raise ProviderError("database_integrity_invalid")
            if database._rows(connection, "PRAGMA foreign_key_check"):
                raise ProviderError("database_foreign_key_invalid")
            history = database.snapshot_history(connection)
            if operation == "prepare":
                filtered = {**history, "runs": tuple(
                    row for row in history["runs"] if row["id"] != evidence["run_id"]
                )}
                database._validate_history(filtered)
            target = (connection.target_path, connection.target_identity)
            database._verify_target_stable(connection)
        finally:
            connection.close()
        loaded = backup.binding._load_policy(str(backup.POLICY_PATH))
        connection = backup.binding._connect_database(database_url)
        try:
            bound = backup.binding.inspect_binding(connection, loaded.policy)
            database._verify_target_stable(connection)
            if (connection.target_path, connection.target_identity) != target:
                raise ProviderError("database_target_changed")
            latest = backup.binding._load_policy(str(backup.POLICY_PATH))
            if latest.raw_bytes != loaded.raw_bytes or latest.policy_sha256 != loaded.policy_sha256:
                raise ProviderError("policy_changed")
        finally:
            connection.close()
        gates = {"history": history, "database_target": target,
                 "bound_profile_id": bound, "policy_bytes": latest.raw_bytes}
        if operation == "prepare":
            _validate_pending(database_url, evidence, gates)
        else:
            _validate_restore_run(database_url, evidence)
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("fresh_gate_failed") from None
    current, current_identity, current_parents = (
        _current_environment(proof) if expected_environment is None else
        _current_environment(proof, expected_identity=expected_environment[0],
                             expected_sha256=expected_environment[1])
    )
    if current != env or current_identity != identity or current_parents != parents:
        raise ProviderError("source_config_changed")
    _validate_original_sources(evidence)
    return env, identity, parents, gates


def _write_receipt(child_fd: int, name: str, record: dict, root_fds, root_ids,
                   root_fd: int, path: Path):
    data = (json.dumps(record, sort_keys=True) + "\n").encode()
    def validate():
        backup._revalidate_root(root_fds, root_ids)
        backup._check_root(root_fd)
        backup._check_child(root_fd, child_fd, path.name)
    try:
        artifacts.write_new_at(
            child_fd, name, data, uid=0, gid=0, mode=0o600, chown=backup._chown_new,
            require_owner=lambda info, uid, gid: backup._require_owner(
                info, uid, gid, "provider_evidence_invalid"), validate_parent=validate,
        )
        os.fsync(child_fd)
        os.fsync(root_fd)
    except Exception:
        raise ProviderError("provider_intent_uncertain", str(path)) from None


def _stage(root_fd: int, parent_fd: int, path: Path, data: bytes):
    name = ".role-radar-provider-" + secrets.token_hex(16)
    fd = None
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProviderError("provider_stage_invalid")
        backup._chown_new(fd, 0, 0)
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        backup._require_owner(info, 0, 0, "provider_stage_invalid")
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1):
            raise ProviderError("provider_stage_invalid")
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise ProviderError("provider_stage_failed")
            view = view[n:]
        os.fsync(fd)
        final = os.fstat(fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (_identity(final) != _identity(named) or final.st_nlink != 1
                or stat.S_IMODE(final.st_mode) != 0o600):
            raise ProviderError("provider_stage_invalid")
        os.fsync(parent_fd)
        return name, fd, _identity(final)
    except ProviderError:
        if fd is not None:
            os.close(fd)
        raise
    except Exception:
        if fd is not None:
            os.close(fd)
        raise ProviderError("provider_stage_failed") from None


def _verify_environment_parent(parent_fds, parent_ids):
    if tuple((os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in parent_fds) != parent_ids:
        raise ProviderError("source_config_changed")
    current, current_ids = backup._open_chain(backup.ENV_PATH.parent)
    try:
        if current_ids != parent_ids:
            raise ProviderError("source_config_changed")
    finally:
        backup._close_all(current)


def _replace_conditional(parent_fd: int, stage_name: str, target_name: str,
                         staged_fd: int, stage_identity, expected_identity):
    current = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
    if _identity(current) != expected_identity:
        raise ProviderError("provider_config_changed")
    staged = os.fstat(staged_fd)
    named_stage = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if (_identity(staged) != stage_identity or _identity(named_stage) != stage_identity
            or stat.S_IMODE(staged.st_mode) != 0o600 or staged.st_nlink != 1):
        raise ProviderError("provider_stage_invalid")
    os.replace(stage_name, target_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    os.fsync(parent_fd)
    installed = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
    if _identity(installed)[:8] != stage_identity[:8]:
        raise ProviderError("provider_outcome_uncertain")
    return _identity(installed)


def _check_transaction_absent(path: Path):
    root_fds = None
    child_fd = None
    try:
        root_fds, _ids = backup._open_chain(backup.BACKUP_ROOT)
        root_fd = root_fds[-1]
        backup._check_root(root_fd)
        child_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                           dir_fd=root_fd)
        backup._check_child(root_fd, child_fd, path.name)
        if any(name in os.listdir(child_fd) for name in (
                RECEIPT_NAME, OUTCOME_NAME, RESTORE_NAME, RESTORE_OUTCOME_NAME)):
            raise ProviderError("transaction_exists", str(path))
    finally:
        if child_fd is not None:
            os.close(child_fd)
        if root_fds:
            backup._close_all(root_fds)


def _prepare(path: Path):
    if os.geteuid() != 0:
        raise ProviderError("operator_privilege_required", str(path))
    _check_transaction_absent(path)
    evidence = _validate_creation(path)
    env, original_id, parents, gates = _fresh_transaction(path, evidence)
    try:
        prepared = prepare_telegram_provider_bytes(env)
    except ProviderBytesError:
        raise ProviderError("provider_config_invalid", str(path)) from None
    root_fds = root_ids = stage_fd = child_fd = None
    try:
        root_fds, root_ids = backup._open_chain(backup.BACKUP_ROOT)
        root_fd = root_fds[-1]
        backup._check_root(root_fd)
        child_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        _check_evidence_child(root_fd, child_fd, path, evidence)
        if any(name in os.listdir(child_fd) for name in (RECEIPT_NAME, OUTCOME_NAME, RESTORE_NAME)):
            raise ProviderError("transaction_exists", str(path))
        env_parent_fds, env_parent_ids = backup._open_chain(backup.ENV_PATH.parent)
        parent_fd = env_parent_fds[-1]
        if env_parent_ids != parents or backup._identity(os.fstat(parent_fd))[:2] != parents[-1]:
            raise ProviderError("source_config_changed", str(path))
        stage_name, stage_fd, stage_identity = _stage(root_fd, parent_fd, backup.ENV_PATH, prepared)
        receipt = {
            "schema_version": RECEIPT_VERSION, "state": "prepared",
            "run_id": evidence["run_id"], "profile_id": evidence["profile_id"],
            "backup": str(path), "backup_identity": list(evidence["backup_identity"]),
            "original_identity": list(original_id), "prepared_identity": list(stage_identity),
            "original_sha256": _sha(env), "prepared_sha256": _sha(prepared),
            "source_proof_sha256": _sha(json.dumps(
                evidence["source_proof"], sort_keys=True, separators=(",", ":")
            ).encode()),
        }
        _write_receipt(child_fd, RECEIPT_NAME, receipt, root_fds, root_ids,
                       root_fd, path)
        # Revalidate retained evidence and fresh source gates after intent, before replacement.
        _revalidate_creation(path, evidence)
        _check_evidence_child(root_fd, child_fd, path, evidence)
        _fresh_transaction(path, evidence, expected_environment=(list(original_id), _sha(env)),
                           operation="prepare")
        backup._revalidate_root(root_fds, root_ids)
        backup._check_child(root_fd, child_fd, path.name)
        _verify_environment_parent(env_parent_fds, env_parent_ids)
        current = backup._fixed_file(backup.ENV_PATH, mode=0o600, gid=0)
        if current[1] != original_id or current[0] != env or current[2] != parents:
            raise ProviderError("provider_config_changed", str(path))
        installed_identity = _replace_conditional(
            parent_fd, stage_name, backup.ENV_PATH.name, stage_fd, stage_identity, original_id
        )
        _write_receipt(child_fd, OUTCOME_NAME,
                       {"schema_version": 1, "state": "prepared", "run_id": evidence["run_id"],
                        "prepared_identity": list(installed_identity),
                        "prepared_sha256": _sha(prepared)},
                       root_fds, root_ids, root_fd, path)
        return receipt
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("provider_transaction_uncertain", str(path)) from None
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if child_fd is not None:
            os.close(child_fd)
        if root_fds:
            backup._close_all(root_fds)
        if "env_parent_fds" in locals():
            backup._close_all(env_parent_fds)


def _restore(path: Path):
    if os.geteuid() != 0:
        raise ProviderError("operator_privilege_required", str(path))
    evidence = _validate_creation(path)
    root_fds = root_ids = child_fd = stage_fd = None
    try:
        root_fds, root_ids = backup._open_chain(backup.BACKUP_ROOT)
        root_fd = root_fds[-1]
        backup._check_root(root_fd)
        child_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        _check_evidence_child(root_fd, child_fd, path, evidence)
        if RESTORE_NAME in os.listdir(child_fd):
            raise ProviderError("transaction_exists", str(path))
        receipt_data, _ = _read_private(child_fd, RECEIPT_NAME)
        receipt = _json(receipt_data)
        outcome_data, _ = _read_private(child_fd, OUTCOME_NAME)
        outcome = _json(outcome_data)
        required = {"schema_version", "state", "run_id", "profile_id", "backup",
                    "backup_identity", "original_identity", "prepared_identity",
                    "original_sha256", "prepared_sha256", "source_proof_sha256"}
        if (type(outcome) is not dict or set(outcome) != {
                    "schema_version", "state", "run_id", "prepared_identity", "prepared_sha256"
                } or type(outcome.get("schema_version")) is not int
                or outcome.get("schema_version") != 1 or outcome.get("state") != "prepared"
                or outcome.get("run_id") != evidence["run_id"]
                or type(outcome.get("prepared_identity")) is not list
                or type(receipt.get("prepared_identity")) is not list
                or outcome["prepared_identity"][:8] != receipt["prepared_identity"][:8]
                or outcome.get("prepared_sha256") != receipt.get("prepared_sha256")
                or type(receipt) is not dict or set(receipt) != required
                or type(receipt.get("schema_version")) is not int
                or receipt["schema_version"] != RECEIPT_VERSION
                or receipt.get("state") != "prepared" or receipt.get("backup") != str(path)
                or receipt.get("run_id") != evidence["run_id"]
                or receipt.get("profile_id") != evidence["profile_id"]
                or receipt.get("backup_identity") != list(evidence["backup_identity"])):
            raise ProviderError("provider_evidence_invalid", str(path))
        proof_hash = _sha(json.dumps(evidence["source_proof"], sort_keys=True,
                                     separators=(",", ":")).encode())
        source_env = evidence["source_proof"]["source"]["environment"]
        if (receipt["source_proof_sha256"] != proof_hash
                or receipt["original_identity"] != source_env["identity"]
                or receipt["original_sha256"] != source_env["sha256"]
                or not _valid_identity(receipt["original_identity"])
                or not _valid_identity(receipt["prepared_identity"])
                or type(receipt["backup_identity"]) is not list
                or len(receipt["backup_identity"]) != 6
                or any(type(item) is not int or item < 0
                       for item in receipt["backup_identity"])
                or not _valid_digest(receipt["original_sha256"])
                or not _valid_digest(receipt["prepared_sha256"])
                or not _valid_identity(outcome.get("prepared_identity"))
                or not _valid_digest(outcome.get("prepared_sha256"))):
            raise ProviderError("provider_evidence_invalid", str(path))
        current, current_id, parents = _current_environment(
            evidence["source_proof"], expected_identity=outcome["prepared_identity"],
            expected_sha256=outcome["prepared_sha256"],
        )
        original, _original_identity, _ = creation._read_at(
            child_fd, "role-radar.env", maximum=backup.MAX_CONFIG_BYTES
        )
        if _sha(original) != receipt["original_sha256"]:
            raise ProviderError("provider_evidence_invalid", str(path))
        env, identity, current_parents, gates = _fresh_transaction(
            path, evidence, expected_environment=(outcome["prepared_identity"],
                                                  outcome["prepared_sha256"]),
            operation="restore",
        )
        if env != current or identity != current_id or current_parents != parents:
            raise ProviderError("provider_config_changed", str(path))
        parent_fds, parent_ids = backup._open_chain(backup.ENV_PATH.parent)
        parent_fd = parent_fds[-1]
        if parent_ids != parents:
            raise ProviderError("source_config_changed", str(path))
        stage_name, stage_fd, stage_identity = _stage(root_fd, parent_fd, backup.ENV_PATH, original)
        intent = {"schema_version": 1, "state": "restore_attempted", "backup": str(path),
                  "run_id": evidence["run_id"], "prepared_identity": list(identity),
                  "restore_identity": list(stage_identity),
                  "prepared_sha256": _sha(current), "original_sha256": _sha(original)}
        _write_receipt(child_fd, RESTORE_NAME, intent, root_fds, root_ids, root_fd, path)
        _revalidate_creation(path, evidence)
        _check_evidence_child(root_fd, child_fd, path, evidence)
        _fresh_transaction(path, evidence, expected_environment=(
            outcome["prepared_identity"], outcome["prepared_sha256"]
        ), operation="restore")
        backup._revalidate_root(root_fds, root_ids)
        backup._check_child(root_fd, child_fd, path.name)
        _verify_environment_parent(parent_fds, parent_ids)
        check = backup._fixed_file(backup.ENV_PATH, mode=0o600, gid=0)
        if check[0] != current or check[1] != identity or check[2] != parents:
            raise ProviderError("provider_config_changed", str(path))
        restored_identity = _replace_conditional(
            parent_fd, stage_name, backup.ENV_PATH.name, stage_fd, stage_identity, identity
        )
        try:
            _write_receipt(
                child_fd, RESTORE_OUTCOME_NAME,
                {"schema_version": 1, "state": "restored", "run_id": evidence["run_id"],
                 "restored_identity": list(restored_identity),
                 "restored_sha256": _sha(original)},
                root_fds, root_ids, root_fd, path,
            )
        except ProviderError:
            raise ProviderError("provider_restore_uncertain", str(path)) from None
        return intent
    except ProviderError:
        raise
    except Exception:
        raise ProviderError("provider_restore_uncertain", str(path)) from None
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if child_fd is not None:
            os.close(child_fd)
        if root_fds:
            backup._close_all(root_fds)
        if "parent_fds" in locals():
            backup._close_all(parent_fds)


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ProviderError("arguments_invalid")


def main(argv=None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if sum(token == "--backup" or token.startswith("--backup=") for token in tokens) > 1:
        print("TELEGRAM_PROVIDER: FAIL (arguments_invalid)", file=sys.stderr)
        return 1
    parser = _Parser(
        description="Prepare or conditionally restore the bounded Telegram provider setting.",
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="action", required=True, parser_class=_Parser)
    for action in ("prepare", "restore"):
        command = sub.add_parser(action, allow_abbrev=False)
        command.add_argument("--backup", required=True,
                             help="completed protected canary backup directory")
    try:
        args = parser.parse_args(argv)
        if not os.path.isabs(args.backup) or os.path.normpath(args.backup) != args.backup:
            raise ProviderError("arguments_invalid")
        path = Path(args.backup)
        if path.parent != backup.BACKUP_ROOT or not creation.BACKUP_NAME.fullmatch(path.name):
            raise ProviderError("backup_path_invalid")
        if args.action == "prepare":
            _prepare(path)
            print("TELEGRAM_PROVIDER: PASS (prepared)")
        else:
            _restore(path)
            print("TELEGRAM_PROVIDER: PASS (restored)")
        return 0
    except SystemExit:
        raise
    except ProviderError as exc:
        recovery = exc.recovery or (str(path) if "path" in locals() else None)
        suffix = f"; recovery={recovery}" if recovery else ""
        print(f"TELEGRAM_PROVIDER: FAIL ({exc.code}{suffix})", file=sys.stderr)
        return 1
    except Exception:
        print("TELEGRAM_PROVIDER: FAIL (provider_transaction_failed)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
