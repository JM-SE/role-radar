from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import pytest

from scripts import bounded_canary_backup as adapter


def _database(path: Path, *, wal: bool = False) -> sqlite3.Connection:
    db = sqlite3.connect(path, isolation_level=None)
    if wal:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        db.execute("PRAGMA wal_autocheckpoint=0")
    db.executescript(
        """
        CREATE TABLE alembic_version (version_num TEXT NOT NULL);
        INSERT INTO alembic_version VALUES ('aa04_bounded_canary_execution');
        CREATE TABLE job_search_runs (
          id TEXT PRIMARY KEY, status TEXT NOT NULL, profile_id TEXT, started_at TEXT,
          completed_at TEXT, claimed_by TEXT, lease_expires_at TEXT, heartbeat_at TEXT,
          recovery_count INTEGER, canary_budget_json TEXT, canary_checkpoint_json TEXT
        );
        CREATE TABLE notification_batches (id TEXT, run_id TEXT, status TEXT NOT NULL);
        CREATE TABLE notification_items (id TEXT, batch_id TEXT, run_id TEXT, status TEXT NOT NULL);
        CREATE TABLE private_payload_fixture (body TEXT);
        """
    )
    db.execute(
        "INSERT INTO job_search_runs VALUES "
        "('private-run-marker','deferred',NULL,NULL,NULL,NULL,NULL,NULL,1,NULL,NULL)"
    )
    db.execute("INSERT INTO private_payload_fixture VALUES ('private-row-marker')")
    return db


def _gate_data(database_url, policy_bytes):
    path = adapter.database._database_path(database_url)
    return {
        "history": None, "policy_bytes": policy_bytes, "policy_sha256": "fixture",
        "database_target": (path, adapter.database._file_identity(path)),
    }


def _fixture(tmp_path, monkeypatch, *, wal=False):
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o755)
    os.chmod(backups, 0o755)
    env = tmp_path / "role-radar.env"
    env.write_bytes(b"TOKEN=secret-config-marker\n")
    env.chmod(0o600)
    policy = tmp_path / "policy.toml"
    policy.write_bytes(b"secret-policy-marker = true\n")
    policy.chmod(0o640)
    db = tmp_path / "live.db"
    writer = _database(db, wal=wal)
    monkeypatch.setattr(adapter, "BACKUP_ROOT", backups)
    monkeypatch.setattr(adapter, "ENV_PATH", env)
    monkeypatch.setattr(adapter, "POLICY_PATH", policy)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)  # Simulated root operator boundary.

    def model_root_owner(_info, uid, gid, _code):
        assert uid == 0 and gid in (0, policy.stat().st_gid)

    # Simulate only UID/GID/chown; fixture bytes, modes and SQLite files are real.
    monkeypatch.setattr(adapter, "_require_owner", model_root_owner)
    monkeypatch.setattr(adapter, "_require_created_by_process", lambda _info, _code: None)
    monkeypatch.setattr(adapter, "_chown_new", lambda _fd, _uid, _gid: None)
    monkeypatch.setattr(
        adapter.binding, "production_discovery_policy_file_policy",
        lambda: type("PolicyMetadata", (), {"group_gid": policy.stat().st_gid})(),
    )
    monkeypatch.setattr(
        adapter, "_fresh_gates",
        lambda database_url, *_args, **_kwargs: _gate_data(database_url, policy.read_bytes()),
    )
    return backups, env, policy, db, writer


def _state(directory: Path):
    return sorted(
        (p.name, stat.S_IMODE(p.stat().st_mode), p.stat().st_nlink)
        for p in directory.iterdir()
    )


def test_online_wal_backup_is_private_consistent_and_does_not_change_source(tmp_path, monkeypatch):
    _backups, env, policy, source, writer = _fixture(tmp_path, monkeypatch, wal=True)
    before_main = hashlib.sha256(source.read_bytes()).hexdigest()
    before_wal = hashlib.sha256(Path(f"{source}-wal").read_bytes()).hexdigest()
    before_changes = writer.total_changes
    writer.execute("SELECT count(*) FROM job_search_runs").fetchone()
    def open_fds():
        result = {}
        for fd in os.listdir("/proc/self/fd"):
            with suppress(OSError):
                result[fd] = os.readlink(f"/proc/self/fd/{fd}")
        return result

    close_observations = []
    original_close = adapter.database._ReadOnlyConnection.close

    def tracked_close(connection):
        before_count = sum(value == str(source) for value in open_fds().values())
        original_close(connection)
        after_count = sum(value == str(source) for value in open_fds().values())
        close_observations.append((before_count, after_count))

    monkeypatch.setattr(adapter.database._ReadOnlyConnection, "close", tracked_close)
    events = []
    def pass_gates(database_url, *_args, **_kwargs):
        events.append("gate")
        return _gate_data(database_url, policy.read_bytes())

    real_mkdir = adapter.os.mkdir
    real_write = adapter._write_new_at
    real_backup = adapter._backup_database

    def observe_mkdir(name, mode=0o777, *, dir_fd=None):
        if str(name).startswith("canary-"):
            events.append("mkdir")
        return real_mkdir(name, mode, dir_fd=dir_fd)

    def observe_write(root_fds, root_ids, root_fd, child_fd, child_name, name, data):
        events.append(name)
        return real_write(root_fds, root_ids, root_fd, child_fd, child_name, name, data)

    def observe_backup(*args):
        events.append("online-copy")
        return real_backup(*args)

    monkeypatch.setattr(adapter, "_fresh_gates", pass_gates)
    monkeypatch.setattr(adapter.os, "mkdir", observe_mkdir)
    monkeypatch.setattr(adapter, "_write_new_at", observe_write)
    monkeypatch.setattr(adapter, "_backup_database", observe_backup)

    recovery = adapter.create_backup(f"sqlite:///{source}")

    assert events.count("gate") == 4
    assert events.index("gate") < events.index("mkdir") < events.index("intent.json")
    assert (recovery / "role-radar.db").stat().st_uid == os.getuid()
    assert (recovery / "role-radar.db").stat().st_gid == os.getgid()
    assert events.index("role-radar.env") < events.index("online-copy")
    assert events.index("discovery-policy.toml") < events.index("online-copy")
    assert events.index("online-copy") < events.index("history.json")
    last_gate = max(i for i, value in enumerate(events) if value == "gate")
    assert events.index("history.json") < last_gate < events.index("result.json")
    assert stat.S_IMODE(recovery.stat().st_mode) == 0o700
    assert _state(recovery) == [
        ("discovery-policy.toml", 0o600, 1), ("history.json", 0o600, 1),
        ("intent.json", 0o600, 1), ("result.json", 0o600, 1),
        ("role-radar.db", 0o600, 1), ("role-radar.env", 0o600, 1),
    ]
    assert (recovery / "role-radar.env").read_bytes() == env.read_bytes()
    assert (recovery / "discovery-policy.toml").read_bytes() == policy.read_bytes()
    history = json.loads((recovery / "history.json").read_text())
    assert history["runs"][0]["id"] == "private-run-marker"
    assert history["runs"][0]["status"] == "deferred"
    result = json.loads((recovery / "result.json").read_text())
    assert result["state"] == "created"
    assert result["record_counts"] == {"runs": 1, "batches": 0, "items": 0}
    assert source.read_bytes() and hashlib.sha256(source.read_bytes()).hexdigest() == before_main
    assert hashlib.sha256(Path(f"{source}-wal").read_bytes()).hexdigest() == before_wal
    assert writer.total_changes == before_changes
    assert close_observations and all(before == after for before, after in close_observations)
    assert str(recovery / "role-radar.db") not in open_fds().values()
    copy = sqlite3.connect(recovery / "role-radar.db")
    assert copy.execute("SELECT id FROM job_search_runs").fetchone() == ("private-run-marker",)
    assert copy.execute("SELECT body FROM private_payload_fixture").fetchone() == (
        "private-row-marker",
    )
    copy.close()
    writer.close()


def test_public_cli_success_has_fixed_output_and_only_recovery_location(
    tmp_path, monkeypatch, capsys
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "c" * 32)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 0
    captured = capsys.readouterr()
    assert captured.out == (
        f"PROTECTED_BACKUP: PASS (backup complete; recovery={backups}/canary-{'c' * 32})\n"
    )
    assert captured.err == ""
    assert "secret-config-marker" not in captured.out + captured.err
    assert "secret-policy-marker" not in captured.out + captured.err
    assert "private-row-marker" not in captured.out + captured.err
    assert "private-run-marker" not in captured.out + captured.err
    writer.close()


def test_rejected_fresh_gate_has_exact_privacy_output_and_no_backup_mutation(
    tmp_path, monkeypatch, capsys
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    before = set(backups.iterdir())
    before_changes = writer.total_changes
    def reject_gate(*_args, **_kwargs):
        raise adapter.BackupError("run_history_unresolved")

    monkeypatch.setattr(adapter, "_fresh_gates", reject_gate)
    monkeypatch.setattr(adapter, "DB_URL", f"sqlite:///{db}")
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "f" * 32)
    assert adapter.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (run_history_unresolved; creation=not_created; "
        f"recovery={backups}/canary-{'f' * 32})\n"
    )
    assert set(backups.iterdir()) == before
    assert writer.total_changes == before_changes
    assert "private" not in captured.out + captured.err
    writer.close()


def test_gate_composition_uses_actual_gate_helpers_in_order_before_mutation(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        adapter.preflight, "run_gate",
        lambda run_id, runner=None: calls.append(("isolation", run_id, runner)),
    )
    monkeypatch.setattr(adapter.provenance, "verify_sources", lambda: calls.append(("source",)))
    monkeypatch.setattr(
        adapter.database, "_connect_database", lambda _url: _connection_proxy(calls)
    )
    monkeypatch.setattr(adapter.binding, "_load_policy", lambda _path: _loaded_policy())
    monkeypatch.setattr(adapter.binding, "_connect_database", lambda _url: _connection_proxy(calls))
    monkeypatch.setattr(adapter.binding, "inspect_binding", lambda *_: calls.append(("binding",)))
    monkeypatch.setattr(
        adapter.database, "_inspect", lambda _connection: calls.append(("db-inspect",))
    )
    monkeypatch.setattr(
        adapter.database, "snapshot_history",
        lambda _connection: {"runs": (), "batches": (), "items": ()},
    )
    monkeypatch.setattr(
        adapter.database, "_verify_target_stable", lambda _connection: calls.append(("db-stable",))
    )
    monkeypatch.setattr(adapter.binding, "_load_policy", lambda _path: _loaded_policy())
    assert adapter._fresh_gates("sqlite:///fixture.db", systemd_runner="fake") == {
        "history": {"runs": (), "batches": (), "items": ()},
        "probe_run_id": calls[0][1], "policy_bytes": b"fixed", "policy_sha256": "fixed",
        "database_target": (Path("fixture.db"), (1, 2, 3, 4, 5, 6, 7)),
    }
    assert calls[0][0] == "isolation" and len(calls[0][1]) == 36
    assert calls[0][2] == "fake"
    gate_calls = [
        item[0] for item in calls
        if item[0] in {"isolation", "source", "db-inspect", "binding"}
    ]
    assert gate_calls == [
        "isolation", "source", "db-inspect", "binding"
    ]


def _connection_proxy(calls):
    class Connection:
        target_path = Path("fixture.db")
        target_identity = (1, 2, 3, 4, 5, 6, 7)

        def close(self):
            calls.append(("close",))
    return Connection()


def _loaded_policy():
    class Loaded:
        raw_bytes = b"fixed"
        policy_sha256 = "fixed"
        policy = object()
    return Loaded()


def test_new_files_are_private_before_first_payload_write(tmp_path, monkeypatch):
    _backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    real_write = os.write
    observed = []

    def checked_write(fd, data):
        info = os.fstat(fd)
        if info.st_size == 0:
            observed.append((stat.S_IMODE(info.st_mode), info.st_nlink, stat.S_ISREG(info.st_mode)))
        return real_write(fd, data)

    monkeypatch.setattr(adapter.os, "write", checked_write)
    recovery = adapter.create_backup(f"sqlite:///{db}")
    assert observed and all(item == (0o600, 1, True) for item in observed)
    assert stat.S_IMODE(recovery.stat().st_mode) == 0o700
    writer.close()


def test_partial_failure_is_retained_and_never_reports_zeroed_completion(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "a" * 32)
    def fail_database(*_args):
        raise adapter.BackupError("database_backup_failed")

    monkeypatch.setattr(adapter, "_backup_database", fail_database)
    with pytest.raises(adapter.BackupError, match="database_backup_failed"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = backups / f"canary-{'a' * 32}"
    record = json.loads((recovery / "partial.json").read_text())
    assert record["state"] == "partial" and record["database"] == "attempted"
    assert record["environment"] == "created" and record["policy"] == "created"
    assert (recovery / "role-radar.env").exists() and (recovery / "discovery-policy.toml").exists()
    assert not (recovery / "result.json").exists()
    writer.close()


def test_existing_recovery_collision_is_not_touched(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    existing = backups / f"canary-{'b' * 32}"
    existing.mkdir(mode=0o700)
    sentinel = existing / "keep"
    sentinel.write_bytes(b"preserve")
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "b" * 32)
    with pytest.raises(adapter.BackupError, match="backup_collision"):
        adapter.create_backup(f"sqlite:///{db}")
    assert sentinel.read_bytes() == b"preserve"
    assert sorted(p.name for p in existing.iterdir()) == ["keep"]
    writer.close()


def test_nonroot_operator_fails_before_gates_or_file_reads(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 1234)
    monkeypatch.setattr(adapter, "_fresh_gates", lambda *_args, **_kwargs: events.append("gate"))
    monkeypatch.setattr(adapter, "_fixed_file", lambda path: events.append(("read", path)))
    with pytest.raises(adapter.BackupError, match="operator_privilege_required"):
        adapter.create_backup(f"sqlite:///{db}")
    assert events == []
    assert list(backups.iterdir()) == []
    writer.close()


def test_backup_root_contract_rejects_wrong_mode_before_child_creation(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    backups.chmod(0o700)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    with pytest.raises(adapter.BackupError, match="backup_root_invalid"):
        adapter.create_backup(f"sqlite:///{db}")
    assert list(backups.iterdir()) == []
    writer.close()


def test_failed_mkdir_reports_planned_path_without_partial_collision_write(
    tmp_path, monkeypatch, capsys
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "d" * 32)
    real_mkdir = os.mkdir

    def fail_planned(path, mode=0o777, *, dir_fd=None):
        if Path(path).name == f"canary-{'d' * 32}":
            raise PermissionError("private filesystem detail")
        return real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(adapter.os, "mkdir", fail_planned)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (backup_create_failed; creation=unknown; "
        f"recovery={backups}/canary-{'d' * 32})\n"
    )
    assert list(backups.iterdir()) == []
    writer.close()


def test_collision_cli_reports_planned_path_and_preserves_existing_child(
    tmp_path, monkeypatch, capsys
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "8" * 32)
    existing = backups / f"canary-{'8' * 32}"
    existing.mkdir(mode=0o700)
    (existing / "keep").write_bytes(b"preserved")
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"PROTECTED_BACKUP: FAIL (backup_collision; creation=collision; recovery={existing})\n"
    )
    assert (existing / "keep").read_bytes() == b"preserved"
    assert sorted(p.name for p in existing.iterdir()) == ["keep"]
    writer.close()


def test_child_open_failure_reports_unknown_without_writing_partial(tmp_path, monkeypatch, capsys):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "6" * 32)
    real_open = os.open

    def fail_new_child(path, flags, *args, **kwargs):
        if path == f"canary-{'6' * 32}" and kwargs.get("dir_fd") is not None:
            raise PermissionError("private child detail")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(adapter.os, "open", fail_new_child)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'6' * 32}"
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (backup_child_unavailable; creation=unknown; "
        f"recovery={recovery})\n"
    )
    assert recovery.is_dir() and list(recovery.iterdir()) == []
    writer.close()


def test_intent_write_failure_is_attempted_not_false_completed(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "e" * 32)
    original_write = adapter._write_new_at

    def fail_intent(root_fds, root_ids, root_fd, child_fd, child_name, name, data):
        if name == "intent.json":
            raise adapter.BackupError("artifact_write_failed")
        return original_write(root_fds, root_ids, root_fd, child_fd, child_name, name, data)

    monkeypatch.setattr(adapter, "_write_new_at", fail_intent)
    with pytest.raises(adapter.BackupError, match="artifact_write_failed"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = backups / f"canary-{'e' * 32}"
    partial = json.loads((recovery / "partial.json").read_text())
    assert partial["intent"] == "attempted"
    assert partial["environment"] == "not_created"
    assert partial["database"] == "not_created"
    writer.close()


def test_policy_is_revalidated_after_final_gate_before_copy(tmp_path, monkeypatch):
    backups, _env, policy, db, writer = _fixture(tmp_path, monkeypatch)
    policy.write_bytes(b"stale-policy-marker = true\n")
    policy.chmod(0o640)
    calls = []

    def gate(*_args, **_kwargs):
        calls.append(1)
        validated = policy.read_bytes()
        return {
            **_gate_data(f"sqlite:///{db}", validated),
            "history": {},
            "policy_bytes": validated if len(calls) < 3 else b"changed-after-final-gate",
        }

    monkeypatch.setattr(adapter, "_fresh_gates", gate)
    with pytest.raises(adapter.BackupError, match="policy_changed"):
        adapter.create_backup(f"sqlite:///{db}")
    assert len(calls) == 3
    assert list(backups.iterdir()) == []
    writer.close()


def test_capacity_failure_is_proved_before_first_backup_mutation(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    monkeypatch.setattr(adapter, "_available_bytes", lambda _path: 0)
    with pytest.raises(adapter.BackupError, match="backup_capacity_unavailable"):
        adapter.create_backup(f"sqlite:///{db}")
    assert list(backups.iterdir()) == []
    writer.close()


def test_nonroot_cli_failure_is_exact_and_precedes_all_gates(tmp_path, monkeypatch, capsys):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(adapter, "_fresh_gates", lambda *_: calls.append("gate"))
    monkeypatch.setattr(adapter, "DB_URL", f"sqlite:///{db}")
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "9" * 32)
    assert adapter.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (operator_privilege_required; creation=not_created; "
        f"recovery={backups}/canary-{'9' * 32})\n"
    )
    assert calls == [] and list(backups.iterdir()) == []
    writer.close()


def test_owner_contract_checks_modeled_root_and_rejects_wrong_uid_gid():
    from types import SimpleNamespace

    adapter._require_owner(SimpleNamespace(st_uid=0, st_gid=0), 0, 0, "owner_invalid")
    adapter._require_created_by_process(
        SimpleNamespace(st_uid=os.geteuid(), st_gid=os.getegid()), "created_invalid"
    )
    with pytest.raises(adapter.BackupError, match="created_invalid"):
        adapter._require_created_by_process(
            SimpleNamespace(st_uid=os.geteuid() + 1, st_gid=os.getegid()), "created_invalid"
        )
    with pytest.raises(adapter.BackupError, match="owner_invalid"):
        adapter._require_owner(SimpleNamespace(st_uid=1000, st_gid=0), 0, 0, "owner_invalid")
    with pytest.raises(adapter.BackupError, match="owner_invalid"):
        adapter._require_owner(SimpleNamespace(st_uid=0, st_gid=2000), 0, 0, "owner_invalid")


def test_artifact_mode_is_checked_before_private_payload_write(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    real_fchmod = os.fchmod

    def weaken_env(fd, mode):
        if os.readlink(f"/proc/self/fd/{fd}").endswith("/role-radar.env"):
            return real_fchmod(fd, 0o644)
        return real_fchmod(fd, mode)

    monkeypatch.setattr(adapter.os, "fchmod", weaken_env)
    with pytest.raises(adapter.BackupError, match="artifact_metadata_invalid"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = next(backups.iterdir())
    copied = recovery / "role-radar.env"
    assert copied.stat().st_size == 0
    assert json.loads((recovery / "partial.json").read_text())["environment"] == "attempted"
    writer.close()


def test_new_child_chown_failure_does_not_write_unverified_partial(tmp_path, monkeypatch, capsys):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "7" * 32)
    def fail_child_chown(fd, uid, gid):
        if os.readlink(f"/proc/self/fd/{fd}").endswith(f"canary-{'7' * 32}"):
            raise OSError("private owner detail")

    monkeypatch.setattr(adapter, "_chown_new", fail_child_chown)
    original_owner = adapter._require_owner

    def reject_unowned_child(info, uid, gid, code):
        if code == "backup_child_owner_invalid":
            raise adapter.BackupError(code)
        return original_owner(info, uid, gid, code)

    monkeypatch.setattr(adapter, "_require_owner", reject_unowned_child)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'7' * 32}"
    assert captured.out == ""
    assert captured.err == (
        f"PROTECTED_BACKUP: FAIL (backup_failed; creation=created; recovery={recovery})\n"
    )
    assert recovery.is_dir() and list(recovery.iterdir()) == []
    writer.close()


def test_intent_fsync_failure_retains_attempted_state(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    real_fsync, failed = os.fsync, False

    def fail_once(fd):
        nonlocal failed
        if not failed and os.readlink(f"/proc/self/fd/{fd}").endswith("/intent.json"):
            failed = True
            raise OSError("private sync detail")
        return real_fsync(fd)

    monkeypatch.setattr(adapter.os, "fsync", fail_once)
    with pytest.raises(adapter.BackupError, match="artifact_write_failed"):
        adapter.create_backup(f"sqlite:///{db}")
    partial = json.loads((next(backups.iterdir()) / "partial.json").read_text())
    assert partial["intent"] == "attempted" and partial["environment"] == "not_created"
    writer.close()


def test_invalid_database_url_is_rejected_before_gate_or_filesystem_effects(
    tmp_path, monkeypatch, capsys
):
    backups, _env, _policy, _db, writer = _fixture(tmp_path, monkeypatch)
    called = []
    monkeypatch.setattr(adapter, "_fresh_gates", lambda *_: called.append("gate"))
    assert adapter.main(["--database-url", "postgres://private-marker"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "PROTECTED_BACKUP: FAIL (database_target_invalid)\n"
    assert called == [] and list(backups.iterdir()) == []
    assert "private-marker" not in captured.err
    writer.close()


def test_config_replacement_after_copy_is_detected_and_retained(tmp_path, monkeypatch):
    backups, env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    original_write = adapter._write_new_at

    def replace_after_env_copy(root_fds, root_ids, root_fd, child_fd, child_name, name, data):
        result = original_write(root_fds, root_ids, root_fd, child_fd, child_name, name, data)
        if name == "role-radar.env":
            env.write_bytes(b"CHANGED=secret-marker\\n")
            env.chmod(0o600)
        return result

    monkeypatch.setattr(adapter, "_write_new_at", replace_after_env_copy)
    with pytest.raises(adapter.BackupError, match="config_changed"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = next(backups.iterdir())
    partial = json.loads((recovery / "partial.json").read_text())
    assert partial["environment"] == "created"
    assert (recovery / "role-radar.env").read_bytes() == b"TOKEN=secret-config-marker\n"
    writer.close()


def test_destination_inode_drift_fails_before_backup_pages(tmp_path, monkeypatch):
    from types import SimpleNamespace

    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    real_connect, real_stat = sqlite3.connect, os.stat
    target_opened = False

    def connect(path, *args, **kwargs):
        nonlocal target_opened
        connection = real_connect(path, *args, **kwargs)
        if isinstance(path, str) and "/proc/self/fd/" in path:
            target_opened = True
        return connection

    def stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if target_opened and path == "role-radar.db" and kwargs.get("dir_fd") is not None:
            values = {name: getattr(result, name) for name in dir(result)
                      if name.startswith("st_")}
            values["st_ino"] += 1
            return SimpleNamespace(**values)
        return result

    monkeypatch.setattr(adapter.sqlite3, "connect", connect)
    monkeypatch.setattr(adapter.os, "stat", stat)
    with pytest.raises(adapter.BackupError, match="artifact_changed"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = next(backups.iterdir())
    partial = json.loads((recovery / "partial.json").read_text())
    assert partial["database"] == "attempted"
    assert not (recovery / "result.json").exists()
    writer.close()


def test_parent_chain_change_fails_before_child_creation(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    original = adapter._revalidate_root
    calls = []

    def rebind_on_last_precreate_check(root_fds, root_ids):
        calls.append("check")
        if len(calls) == 3:
            raise adapter.BackupError("backup_root_changed")
        return original(root_fds, root_ids)

    monkeypatch.setattr(adapter, "_revalidate_root", rebind_on_last_precreate_check)
    with pytest.raises(adapter.BackupError, match="backup_root_changed"):
        adapter.create_backup(f"sqlite:///{db}")
    assert len(calls) == 3
    assert list(backups.iterdir()) == []
    writer.close()


def test_deadline_and_result_write_failures_leave_truthful_partial_evidence(
    tmp_path, monkeypatch
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter, "DEADLINE_SECONDS", -1)
    with pytest.raises(adapter.BackupError, match="backup_deadline"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = next(backups.iterdir())
    partial = json.loads((recovery / "partial.json").read_text())
    assert partial["database"] == "attempted"
    assert partial["history"] == "not_created"
    assert not (recovery / "result.json").exists()
    writer.close()


def test_result_fsync_failure_records_result_as_attempted(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    real_fsync = os.fsync
    failed = False

    def fail_result_once(fd):
        nonlocal failed
        target = os.readlink(f"/proc/self/fd/{fd}")
        if not failed and target.endswith("/result.json"):
            failed = True
            raise OSError("private fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(adapter.os, "fsync", fail_result_once)
    with pytest.raises(adapter.BackupError, match="artifact_write_failed"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = next(backups.iterdir())
    partial = json.loads((recovery / "partial.json").read_text())
    assert partial["result"] == "attempted"
    assert partial["database"] == partial["history"] == "created"
    writer.close()


def test_chown_failure_prevents_private_payload_write(tmp_path, monkeypatch):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    original_chown = adapter._chown_new

    def fail_env_owner(fd, uid, gid):
        target = os.readlink(f"/proc/self/fd/{fd}")
        if target.endswith("/role-radar.env"):
            raise OSError("private ownership detail")
        original_chown(fd, uid, gid)

    monkeypatch.setattr(adapter, "_chown_new", fail_env_owner)
    with pytest.raises(adapter.BackupError, match="artifact_write_failed"):
        adapter.create_backup(f"sqlite:///{db}")
    recovery = next(backups.iterdir())
    env_copy = recovery / "role-radar.env"
    assert env_copy.exists() and env_copy.stat().st_size == 0
    assert json.loads((recovery / "partial.json").read_text())["environment"] == "attempted"
    writer.close()


@pytest.mark.parametrize("drift", ["mode", "nlink"])
def test_destination_protection_must_hold_before_sqlite_pages(
    tmp_path, monkeypatch, capsys, drift
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "d" * 32)
    before = hashlib.sha256(db.read_bytes()).digest()
    changes = writer.total_changes
    original = adapter._create_empty_at

    def weaken_after_create(*args, **kwargs):
        result = original(*args, **kwargs)
        destination = backups / next(backups.iterdir()).name / "role-radar.db"
        if drift == "mode":
            destination.chmod(0o644)
        else:
            (destination.parent / "extra-link").hardlink_to(destination)
        return result

    monkeypatch.setattr(adapter, "_create_empty_at", weaken_after_create)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'d' * 32}"
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (artifact_metadata_invalid; creation=created; "
        f"recovery={recovery})\n"
    )
    assert (recovery / "role-radar.db").stat().st_size == 0
    assert json.loads((recovery / "partial.json").read_text())["database"] == "attempted"
    assert hashlib.sha256(db.read_bytes()).digest() == before
    assert writer.total_changes == changes
    writer.close()


def test_config_protection_must_hold_before_first_secret_write(tmp_path, monkeypatch, capsys):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "e" * 32)
    before = hashlib.sha256(db.read_bytes()).digest()
    changes = writer.total_changes
    original = adapter._validate_child_path

    def weaken_after_validation(*args, **kwargs):
        original(*args, **kwargs)
        recovery = next(iter(backups.iterdir()), None)
        if recovery is not None:
            env_copy = recovery / "role-radar.env"
            if env_copy.exists() and env_copy.stat().st_size == 0:
                env_copy.chmod(0o644)

    monkeypatch.setattr(adapter, "_validate_child_path", weaken_after_validation)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'e' * 32}"
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (artifact_metadata_invalid; creation=created; "
        f"recovery={recovery})\n"
    )
    assert (recovery / "role-radar.env").read_bytes() == b""
    assert json.loads((recovery / "partial.json").read_text())["environment"] == "attempted"
    assert hashlib.sha256(db.read_bytes()).digest() == before
    assert writer.total_changes == changes
    writer.close()


@pytest.mark.parametrize("replacement", ["leaf", "parent"])
def test_source_database_rebind_during_online_backup_is_rejected(
    tmp_path, monkeypatch, capsys, replacement
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    original_digest = hashlib.sha256(db.read_bytes()).digest()
    original_changes = writer.total_changes
    if replacement == "parent":
        dbdir = tmp_path / "dbdir"
        dbdir.mkdir()
        db.rename(dbdir / db.name)
        db = dbdir / db.name
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "b" * 32)
    original_backup = adapter.database._ReadOnlyConnection.backup
    moved = tmp_path / "original-dbdir"
    old_location = None

    def rebind_parent():
        nonlocal old_location
        db.parent.rename(moved)
        db.parent.mkdir()
        (moved / db.name).rename(db)
        old_location = db

    def substitute_source(connection, *args, **kwargs):
        nonlocal old_location
        if replacement == "leaf":
            old_location = db.with_name("original.db")
            db.rename(old_location)
            shutil.copyfile(old_location, db)
            with sqlite3.connect(db) as replacement_db:
                replacement_db.execute(
                    "UPDATE private_payload_fixture SET body='SYNTHETIC-PRIVATE-NEW'"
                )
            return original_backup(connection, *args, **kwargs)
        result = original_backup(connection, *args, **kwargs)
        rebind_parent()
        return result

    if replacement == "leaf":
        monkeypatch.setattr(adapter.database._ReadOnlyConnection, "backup", substitute_source)
    else:
        original_gate = adapter._fresh_gates
        gate_count = 0

        def rebind_before_final_gate(*args, **kwargs):
            nonlocal gate_count
            result = original_gate(*args, **kwargs)
            gate_count += 1
            if gate_count == 4:
                rebind_parent()
            return result

        monkeypatch.setattr(adapter, "_fresh_gates", rebind_before_final_gate)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'b' * 32}"
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (database_target_changed; creation=created; "
        f"recovery={recovery})\n"
    )
    assert hashlib.sha256(old_location.read_bytes()).digest() == original_digest
    assert writer.total_changes == original_changes
    with sqlite3.connect(old_location) as original_db:
        assert original_db.execute(
            "SELECT body FROM private_payload_fixture"
        ).fetchone() == ("private-row-marker",)
    if replacement == "leaf":
        with sqlite3.connect(db) as replacement_db:
            assert replacement_db.execute(
                "SELECT body FROM private_payload_fixture"
            ).fetchone() == ("SYNTHETIC-PRIVATE-NEW",)
    with sqlite3.connect(recovery / "role-radar.db") as backup_db:
        assert backup_db.execute(
            "SELECT body FROM private_payload_fixture"
        ).fetchone() == ("private-row-marker",)
    assert not (recovery / "result.json").exists()
    expected_state = "attempted" if replacement == "leaf" else "created"
    assert json.loads((recovery / "partial.json").read_text())["database"] == expected_state
    assert "SYNTHETIC-PRIVATE" not in captured.out + captured.err
    writer.close()


def test_config_ancestor_rebind_preserving_leaf_is_rejected(
    tmp_path, monkeypatch, capsys
):
    backups, env, policy, db, writer = _fixture(tmp_path, monkeypatch)
    before_db = hashlib.sha256(db.read_bytes()).digest()
    before_changes = writer.total_changes
    config_parent = tmp_path / "config"
    inner = config_parent / "inner"
    inner.mkdir(parents=True, mode=0o700)
    env_path, policy_path = inner / "runtime.env", inner / "policy.toml"
    env.rename(env_path)
    policy.rename(policy_path)
    monkeypatch.setattr(adapter, "ENV_PATH", env_path)
    monkeypatch.setattr(adapter, "POLICY_PATH", policy_path)
    monkeypatch.setattr(
        adapter.binding, "production_discovery_policy_file_policy",
        lambda: type("PolicyMetadata", (), {"group_gid": policy_path.stat().st_gid})(),
    )

    def config_owner(_info, uid, gid, _code):
        assert uid == 0 and gid in (0, policy_path.stat().st_gid)

    monkeypatch.setattr(adapter, "_require_owner", config_owner)
    monkeypatch.setattr(
        adapter, "_fresh_gates",
        lambda database_url, *_args, **_kwargs: _gate_data(database_url, policy_path.read_bytes()),
    )
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "c" * 32)
    original_write = adapter._write_new_at
    moved_parent = config_parent.with_name("original-config")
    rebound = False

    def rebind_after_environment_copy(*args, **kwargs):
        nonlocal rebound
        result = original_write(*args, **kwargs)
        if args[-2] == "role-radar.env" and not rebound:
            config_parent.rename(moved_parent)
            config_parent.mkdir(mode=0o700)
            (moved_parent / "inner").rename(config_parent / "inner")
            rebound = True
        return result

    monkeypatch.setattr(adapter, "_write_new_at", rebind_after_environment_copy)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'c' * 32}"
    assert captured.out == ""
    assert captured.err == (
        "PROTECTED_BACKUP: FAIL (config_changed; creation=created; "
        f"recovery={recovery})\n"
    )
    assert rebound
    assert (config_parent / "inner" / "runtime.env").read_bytes() == b"TOKEN=secret-config-marker\n"
    assert not (recovery / "result.json").exists()
    assert hashlib.sha256(db.read_bytes()).digest() == before_db
    assert writer.total_changes == before_changes
    assert "secret-config-marker" not in captured.out + captured.err
    writer.close()


def test_config_ancestor_rebind_between_fresh_gates_is_rejected(
    tmp_path, monkeypatch, capsys
):
    backups, env, policy, db, writer = _fixture(tmp_path, monkeypatch)
    config_parent = tmp_path / "config"
    inner = config_parent / "inner"
    inner.mkdir(parents=True, mode=0o700)
    env_path, policy_path = inner / "runtime.env", inner / "policy.toml"
    env.rename(env_path)
    policy.rename(policy_path)
    monkeypatch.setattr(adapter, "ENV_PATH", env_path)
    monkeypatch.setattr(adapter, "POLICY_PATH", policy_path)
    monkeypatch.setattr(
        adapter.binding, "production_discovery_policy_file_policy",
        lambda: type("PolicyMetadata", (), {"group_gid": policy_path.stat().st_gid})(),
    )

    def config_owner(_info, uid, gid, _code):
        assert uid == 0 and gid in (0, policy_path.stat().st_gid)

    monkeypatch.setattr(adapter, "_require_owner", config_owner)
    monkeypatch.setattr(
        adapter, "_fresh_gates",
        lambda database_url, *_args, **_kwargs: _gate_data(database_url, policy_path.read_bytes()),
    )
    original_gate = adapter._fresh_gates
    gate_count = 0
    moved_parent = config_parent.with_name("original-config")

    def rebind_after_gate(database_url, *args, **kwargs):
        nonlocal gate_count
        result = original_gate(database_url, *args, **kwargs)
        gate_count += 1
        if gate_count == 1:
            config_parent.rename(moved_parent)
            config_parent.mkdir(mode=0o700)
            (moved_parent / "inner").rename(config_parent / "inner")
        return result

    monkeypatch.setattr(adapter, "_fresh_gates", rebind_after_gate)
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "a" * 32)
    assert adapter.main(["--database-url", f"sqlite:///{db}"]) == 1
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'a' * 32}"
    assert (captured.out, captured.err) == (
        "", "PROTECTED_BACKUP: FAIL (config_changed; creation=not_created; "
        f"recovery={recovery})\n",
    )
    assert gate_count == 1 and not list(backups.iterdir())
    assert (config_parent / "inner" / "runtime.env").read_bytes() == b"TOKEN=secret-config-marker\n"
    assert "secret-config-marker" not in captured.out + captured.err
    writer.close()


def test_documented_backup_help_entrypoint_needs_no_pythonpath(tmp_path):
    home, temp, cache = (tmp_path / name for name in ("home", "tmp", "cache"))
    for directory in (home, temp, cache):
        directory.mkdir()
    env = {
        "PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp),
        "XDG_CACHE_HOME": str(cache), "UV_OFFLINE": "1",
        "ROLE_RADAR_TEST_NETWORK_DENY": "1", "NO_UPDATE_NOTIFIER": "1",
    }
    root = Path(__file__).resolve().parents[2]
    command = [sys.executable, "-B", "-m", "scripts.bounded_canary_backup", "--help"]
    result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "--database-url" in result.stdout and result.stderr == ""
    assert all(not any(directory.iterdir()) for directory in (home, temp, cache))


def _backup_fd_targets(_db: Path, _backups: Path) -> list[tuple[int, str]]:
    targets = []
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{name}")
        except FileNotFoundError:
            continue
        targets.append((int(name), target))
    return sorted(targets)


@pytest.mark.parametrize("failure", [False, True], ids=["success", "backup-failure"])
def test_backup_owned_file_descriptors_close_on_success_and_failure(
    tmp_path, monkeypatch, capsys, failure
):
    backups, _env, _policy, db, writer = _fixture(tmp_path, monkeypatch)
    writer.close()
    monkeypatch.setattr(adapter.secrets, "token_hex", lambda _n: "f" * 32)
    if failure:
        def fail_backup(_connection, *_args, **_kwargs):
            raise sqlite3.OperationalError("SYNTHETIC-PRIVATE")

        monkeypatch.setattr(adapter.database._ReadOnlyConnection, "backup", fail_backup)
    baseline = _backup_fd_targets(db, backups)
    rc = adapter.main(["--database-url", f"sqlite:///{db}"])
    captured = capsys.readouterr()
    recovery = backups / f"canary-{'f' * 32}"
    if failure:
        assert (rc, captured.out, captured.err) == (
            1, "", "PROTECTED_BACKUP: FAIL (database_backup_failed; creation=created; "
            f"recovery={recovery})\n",
        )
        assert not (recovery / "result.json").exists()
    else:
        assert (rc, captured.out, captured.err) == (
            0, f"PROTECTED_BACKUP: PASS (backup complete; recovery={recovery})\n", "",
        )
    assert _backup_fd_targets(db, backups) == baseline
    assert "SYNTHETIC-PRIVATE" not in captured.out + captured.err


def test_help_and_invalid_arguments_do_not_run_gates(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(adapter, "create_backup", lambda *_args: calls.append("backup"))
    with pytest.raises(SystemExit) as exit_info:
        adapter.main(["--help"])
    assert exit_info.value.code == 0
    assert "does not create or start a run" in capsys.readouterr().out
    assert calls == []
    assert adapter.main(
        ["--database-url=sqlite:///private", "--database-url", "sqlite:///other"]
    ) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "PROTECTED_BACKUP: FAIL (arguments_invalid)\n"
    assert calls == []
    for argv in (["--database-u", "sqlite:///private"], ["--unknown-secret-marker"]):
        assert adapter.main(argv) == 1
        rejected = capsys.readouterr()
        assert rejected.out == ""
        assert rejected.err == "PROTECTED_BACKUP: FAIL (arguments_invalid)\n"
        assert calls == []
