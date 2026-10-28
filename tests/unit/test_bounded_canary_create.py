from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from role_radar.db.base import Base
from role_radar.db.models import CandidateProfile
from role_radar.domain.enums import JobSearchRunStatus
from role_radar.repositories.runs import RunRepository
from scripts import bounded_canary_backup as backup
from scripts import bounded_canary_create as adapter
from tests.unit import test_bounded_canary_binding as binding_tests
from tests.unit import test_bounded_canary_preflight as preflight_tests
from tests.unit import test_bounded_canary_provenance as provenance_tests

REAL_FRESH_GATES = backup._fresh_gates
REAL_PREFLIGHT_RUN_GATE = backup.preflight.run_gate
REAL_PROVENANCE_VERIFY = backup.provenance.verify_sources


def _ready_backup(tmp_path, monkeypatch, *, compose_t1_gates=False):
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o755)
    os.chmod(backups, 0o755)
    env = tmp_path / "role-radar.env"
    env.write_bytes(b"SYNTHETIC_CONFIG=private\n")
    env.chmod(0o600)
    policy = tmp_path / "policy.toml"
    binding_tests._policy_file(policy)
    db = tmp_path / "live.db"
    from role_radar.db.engine import get_engine
    engine = get_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num TEXT NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version VALUES ('aa04_bounded_canary_execution')")
        )
    with Session(engine) as session:
        session.add(CandidateProfile(
            id=binding_tests.PROFILE_ID, name="synthetic", version=1, schema_version=1,
            profile_json=binding_tests.PROFILE, is_active=True,
        ))
        RunRepository(session).create_run(
            "prior fixture", JobSearchRunStatus.DEFERRED,
            profile_id=binding_tests.PROFILE_ID, request_hash="synthetic-old-run",
        )
        session.commit()
    engine.dispose()
    writer = sqlite3.connect(db, isolation_level=None)
    assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    monkeypatch.setattr(backup, "BACKUP_ROOT", backups)
    monkeypatch.setattr(backup, "ENV_PATH", env)
    monkeypatch.setattr(backup, "POLICY_PATH", policy)
    monkeypatch.setattr(backup.os, "geteuid", lambda: 0)
    monkeypatch.setattr(backup, "_require_owner", lambda _info, uid, gid, _code: None)
    monkeypatch.setattr(backup, "_require_created_by_process", lambda _info, _code: None)
    monkeypatch.setattr(backup, "_chown_new", lambda _fd, _uid, _gid: None)
    import role_radar.acquisition.discovery_policy as policy_module
    from role_radar.acquisition.discovery_policy import DiscoveryPolicyFilePolicy
    def policy_factory():
        return DiscoveryPolicyFilePolicy(
            owner_uid=None, group_gid=policy.stat().st_gid, mode=0o640, require_owner=False
        )
    monkeypatch.setattr(backup.binding, "production_discovery_policy_file_policy", policy_factory)
    monkeypatch.setattr(policy_module, "production_discovery_policy_file_policy", policy_factory)
    monkeypatch.setattr(
        policy_module, "_validate_parent_chain",
        lambda parent, _policy: binding_tests._validate_synthetic_parent(parent, policy.parent),
    )
    monkeypatch.setattr(
        DiscoveryPolicyFilePolicy, "validate",
        lambda self, fd: binding_tests._validate_synthetic_metadata(self, fd),
    )
    monkeypatch.setattr(backup, "_fresh_gates", REAL_FRESH_GATES)
    gate_calls = []
    if compose_t1_gates:
        def systemd(command, **_kwargs):
            if command[1] == "list-units":
                return subprocess.CompletedProcess(command, 0, "", "")
            property_arg = next(item for item in command if item.startswith("--property="))
            properties = property_arg.split("=", 1)[1].split(",")
            blocks = []
            for name in command[command.index(property_arg) + 1:]:
                run_id = (
                    name.removeprefix(preflight_tests.CANARY_PREFIX).removesuffix(".service")
                    if name.startswith(preflight_tests.CANARY_PREFIX)
                    else preflight_tests.RUN_ID
                )
                records = preflight_tests._records(run_id)
                values = dict(line.split("=", 1) for line in records[name].splitlines() if line)
                blocks.append("".join(f"{key}={values[key]}\n" for key in properties) + "\n")
            return subprocess.CompletedProcess(command, 0, "".join(blocks), "")

        def isolation(run_id, runner=None):
            gate_calls.append("isolation")
            return REAL_PREFLIGHT_RUN_GATE(run_id, runner=systemd)

        def provenance():
            fs = provenance_tests.MemoryFS()
            result = REAL_PROVENANCE_VERIFY(fs=fs.os(), pins=provenance_tests.PINS)
            provenance_tests._assert_all_fds_closed(fs)
            gate_calls.append("provenance")
            return result

        monkeypatch.setattr(backup.preflight, "run_gate", isolation)
        monkeypatch.setattr(backup.provenance, "verify_sources", provenance)
    else:
        monkeypatch.setattr(
            backup.preflight, "run_gate",
            lambda _run_id, runner=None: gate_calls.append("isolation"),
        )
        monkeypatch.setattr(
            backup.provenance, "verify_sources", lambda: gate_calls.append("provenance")
        )
    monkeypatch.setattr(adapter, "BACKUP_ROOT", backups)
    monkeypatch.setattr(adapter, "APP_ROOT", tmp_path / "opt" / "role-radar")
    monkeypatch.setattr(adapter, "DATABASE_PATH", db.resolve())
    adapter.APP_ROOT.mkdir(parents=True)
    recovery = backup.create_backup(f"sqlite:///{db}")
    assert len(gate_calls) == 8
    return recovery, db, writer, gate_calls


def _simulate_runuser(monkeypatch, profile_id, calls, *, outcome="success"):
    from role_radar.cli.main import main as public_cli

    def run(command, **kwargs):
        calls.append((command, kwargs))
        assert command[:5] == ["/usr/sbin/runuser", "-u", "role-radar", "--", "/usr/bin/env"]
        assert kwargs["timeout"] == 40 and kwargs["shell"] is False
        assert kwargs["cwd"] == adapter.APP_ROOT
        assert kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"}
        env_start = command.index("-i") + 1
        names = ("PATH", "LANG", "HOME", "ROLE_RADAR_DATABASE_URL")
        child_env = dict(item.split("=", 1) for item in command[env_start:env_start + 4])
        assert tuple(child_env) == names
        assert child_env["PATH"] == f"{adapter.APP_ROOT}/.venv/bin:/usr/bin"
        assert child_env["LANG"] == "C" and child_env["HOME"] == str(adapter.APP_ROOT)
        assert command[env_start + 4:] == [
            "role-radar", "run", "create", "--canary", "--profile-id", profile_id,
        ]
        if outcome != "success":
            if outcome == "timeout":
                return None
            if outcome == "nonzero":
                return subprocess.CompletedProcess(command, 1, "private-uuid", "private-stderr")
            return subprocess.CompletedProcess(
                command, 0, '{"id":"not-a-uuid","status":"pending"}', ""
            )
        original = os.environ.copy()
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            os.environ.clear()
            os.environ.update(child_env)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                rc = public_cli(command[env_start + 5:])
            if rc != 0:
                raise AssertionError((rc, stderr.getvalue()))
        finally:
            os.environ.clear()
            os.environ.update(original)
        return subprocess.CompletedProcess(command, rc, stdout.getvalue(), stderr.getvalue())

    monkeypatch.setattr(adapter.subprocess, "run", run)


def test_help_and_invalid_arguments_are_private_and_have_no_effects(monkeypatch):
    opened = []
    monkeypatch.setattr(adapter, "_open_backup", lambda *_: opened.append("backup"))
    help_output = io.StringIO()
    monkeypatch.setattr(adapter.sys, "stdout", help_output)
    with pytest.raises(SystemExit) as help_result:
        adapter.main(["--help"])
    assert help_result.value.code == 0
    assert "never start a worker" in help_output.getvalue()
    assert opened == []

    for argv in (
        [],
        ["--backup", "/tmp/private-marker", "--backup", "/tmp/other"],
        ["--back", "/tmp/private-marker"],
        ["--backup", "relative/private-marker"],
        ["--unknown-private-marker"],
    ):
        out, err = io.StringIO(), io.StringIO()
        monkeypatch.setattr(adapter.sys, "stdout", out)
        monkeypatch.setattr(adapter.sys, "stderr", err)
        assert adapter.main(argv) == 1
        assert out.getvalue() == ""
        assert err.getvalue() == "CANARY_CREATION: FAIL (arguments_invalid)\n"
        assert "private-marker" not in err.getvalue()
    assert opened == []


def test_public_cli_creates_one_pending_canary_and_preserves_history(tmp_path, monkeypatch, capsys):
    recovery, db, writer, gate_calls = _ready_backup(
        tmp_path, monkeypatch, compose_t1_gates=True
    )
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    network_calls = []
    monkeypatch.setattr(socket.socket, "connect", lambda *_: network_calls.append("socket"))
    before_connection = backup.database._connect_database(f"sqlite:///{db}")
    try:
        old_runs = backup.database.snapshot_history(before_connection)
    finally:
        before_connection.close()
    changes = writer.total_changes
    completed_result = json.loads((recovery / "result.json").read_text())
    assert type(completed_result["schema_version"]) is int
    assert all(type(value) is int for value in completed_result["record_counts"].values())
    assert completed_result["record_counts"] == {
        "runs": len(old_runs["runs"]), "batches": len(old_runs["batches"]),
        "items": len(old_runs["items"]),
    }
    rc = adapter.main(["--backup", str(recovery)])
    result = capsys.readouterr()
    assert rc == 0, result
    assert result.out == f"CANARY_CREATION: PASS (recovery={recovery})\n"
    assert result.err == ""
    assert binding_tests.PROFILE_ID not in result.out + result.err
    assert len(calls) == 1 and network_calls == []
    attempt = json.loads((recovery / "create-attempt.json").read_text())
    created = json.loads((recovery / "creation-outcome.json").read_text())
    assert attempt["state"] == "attempted" and attempt["profile_id"] == binding_tests.PROFILE_ID
    assert created["state"] == "created" and created["profile_id"] == binding_tests.PROFILE_ID
    assert created["run_id"] not in result.out + result.err
    connection = backup.database._connect_database(f"sqlite:///{db}")
    try:
        after = backup.database.snapshot_history(connection)
        old_ids = {item["id"] for item in old_runs["runs"]}
        new_runs = [row for row in after["runs"] if row["id"] not in old_ids]
        assert len(new_runs) == 1 and new_runs[0]["id"] == created["run_id"]
        assert new_runs[0]["status"] == "pending"
        assert new_runs[0]["profile_id"] == binding_tests.PROFILE_ID
        assert after["batches"] == old_runs["batches"] and after["items"] == old_runs["items"]
        metadata = adapter._run_metadata(connection)
        assert len(metadata) == len(old_runs["runs"]) + 1
        row = metadata[created["run_id"]]
        from role_radar.execution_budget import CANARY_BUDGET
        assert json.loads(row[0]) == CANARY_BUDGET
        assert json.loads(row[1]) == {
            "version": 1, "stage": "discovery", "cursor": 0, "counts": {},
            "reservations": [], "logical_reservations": [],
        }
    finally:
        connection.close()
    assert writer.total_changes == changes
    assert gate_calls == ["isolation", "provenance"] * 5
    assert set(p.name for p in recovery.iterdir()) == {
        "discovery-policy.toml", "history.json", "intent.json", "result.json",
        "role-radar.db", "role-radar.env", "source-proof.json", "create-attempt.json",
        "creation-outcome.json",
    }
    writer.close()


@pytest.mark.parametrize(
    ("field", "value", "numeric_value"),
    [("schema_version", True, 1), ("count-runs", True, 1), ("count-batches", False, 0)],
)
def test_completed_result_boolean_numbers_reject_before_attempt(
    tmp_path, monkeypatch, capsys, field, value, numeric_value
):
    recovery, db, writer, gate_calls = _ready_backup(
        tmp_path, monkeypatch, compose_t1_gates=True
    )
    assert gate_calls == ["isolation", "provenance"] * 4
    result_path = recovery / "result.json"
    result = json.loads(result_path.read_text())
    if field == "schema_version":
        result[field] = value
    else:
        name = field.removeprefix("count-")
        assert type(result["record_counts"][name]) is int
        assert result["record_counts"][name] == numeric_value == int(value)
        result["record_counts"][name] = value
    result_path.write_text(json.dumps(result, sort_keys=True) + "\n")
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    before = backup.database._connect_database(f"sqlite:///{db}")
    try:
        old_history = backup.database.snapshot_history(before)
    finally:
        before.close()
    changes = writer.total_changes

    rc = adapter.main(["--backup", str(recovery)])
    captured = capsys.readouterr()
    after = backup.database._connect_database(f"sqlite:///{db}")
    try:
        history = backup.database.snapshot_history(after)
    finally:
        after.close()
    observed = (
        rc, captured.out, captured.err, len(calls), history, writer.total_changes - changes,
        (recovery / "create-attempt.json").exists(),
    )
    expected = (
        1, "", f"CANARY_CREATION: FAIL (backup_incomplete; recovery={recovery})\n",
        0, old_history, 0, False,
    )
    assert observed == expected
    assert binding_tests.PROFILE_ID not in captured.out + captured.err
    assert gate_calls == ["isolation", "provenance"] * 4
    writer.close()


def test_policy_replacement_after_intent_is_uncertain_before_child(
    tmp_path, monkeypatch, capsys
):
    recovery, db, writer, gate_calls = _ready_backup(
        tmp_path, monkeypatch, compose_t1_gates=True
    )
    assert gate_calls == ["isolation", "provenance"] * 4
    policy_path = backup.POLICY_PATH
    original_bytes = policy_path.read_bytes()
    loaded = []
    real_load = backup.binding._load_policy

    def load_policy(path):
        value = real_load(path)
        loaded.append(value.raw_bytes)
        return value

    monkeypatch.setattr(backup.binding, "_load_policy", load_policy)
    assert backup.binding._load_policy(str(policy_path)).raw_bytes == original_bytes
    loaded.clear()
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    before = backup.database._connect_database(f"sqlite:///{db}")
    try:
        old_history = backup.database.snapshot_history(before)
    finally:
        before.close()
    changes = writer.total_changes
    injected = []
    original_attempt = adapter._create_attempt

    def replace_policy_after_intent(*args, **kwargs):
        result = original_attempt(*args, **kwargs)
        replacement = original_bytes.replace(b"gate-a-v1", b"gate-a-v2")
        assert replacement != original_bytes
        policy_path.write_bytes(replacement)
        assert real_load(str(policy_path)).raw_bytes == replacement
        injected.append(True)
        return result

    monkeypatch.setattr(adapter, "_create_attempt", replace_policy_after_intent)
    rc = adapter.main(["--backup", str(recovery)])
    captured = capsys.readouterr()
    after = backup.database._connect_database(f"sqlite:///{db}")
    try:
        history = backup.database.snapshot_history(after)
    finally:
        after.close()
    assert loaded and all(payload == original_bytes for payload in loaded)
    assert gate_calls == ["isolation", "provenance"] * 5
    assert injected == [True]
    assert (rc, captured.out, captured.err) == (
        1, "", f"CANARY_CREATION: FAIL (creation_uncertain; recovery={recovery})\n",
    )
    assert calls == [] and history == old_history and writer.total_changes == changes
    assert json.loads((recovery / "create-attempt.json").read_text())["state"] == "attempted"
    outcome = json.loads((recovery / "creation-outcome.json").read_text())
    assert outcome["state"] == "uncertain"
    assert binding_tests.PROFILE_ID not in captured.out + captured.err
    writer.close()


def test_read_creation_evidence_is_private_read_only_and_preserves_create_guard(
    tmp_path, monkeypatch, capsys
):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    assert adapter.main(["--backup", str(recovery)]) == 0
    assert capsys.readouterr().out == f"CANARY_CREATION: PASS (recovery={recovery})\n"
    files_before = {p.name: (p.stat().st_mode, p.stat().st_nlink, p.stat().st_size,
                             p.stat().st_mtime_ns, p.read_bytes())
                    for p in recovery.iterdir()}
    directory_mtime = recovery.stat().st_mtime_ns
    with adapter._open_creation_evidence(recovery) as evidence:
        assert evidence["profile_id"] == binding_tests.PROFILE_ID
        assert evidence["run_id"] == json.loads(
            (recovery / "creation-outcome.json").read_text()
        )["run_id"]
        assert evidence["history"]["runs"]
        assert evidence["child_fd"] >= 0
        assert len(evidence["artifact_identities"]) == 9
    assert capsys.readouterr().out == ""
    assert capsys.readouterr().err == ""
    assert recovery.stat().st_mtime_ns == directory_mtime
    assert files_before == {
        p.name: (p.stat().st_mode, p.stat().st_nlink, p.stat().st_size,
                 p.stat().st_mtime_ns, p.read_bytes()) for p in recovery.iterdir()
    }
    assert adapter.main(["--backup", str(recovery)]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == f"CANARY_CREATION: FAIL (creation_attempt_exists; recovery={recovery})\n"
    assert len(calls) == 1
    writer.close()


@pytest.mark.parametrize("mutation", ["missing-attempt", "missing-outcome", "uncertain",
                                       "profile-mismatch", "run-invalid", "bool-version",
                                       "attempt-profile-invalid", "backup-identity-mismatch"])
def test_read_creation_evidence_rejects_uncertain_or_mismatched_receipts(
    tmp_path, monkeypatch, capsys, mutation
):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    assert adapter.main(["--backup", str(recovery)]) == 0
    target = recovery / ("create-attempt.json" if mutation in {
        "missing-attempt", "attempt-profile-invalid", "backup-identity-mismatch"
    } else "creation-outcome.json")
    if mutation.startswith("missing-"):
        original_open = adapter.os.open
        def absent(name, flags, *args, **kwargs):
            if name == target.name and kwargs.get("dir_fd") is not None:
                raise FileNotFoundError(name)
            return original_open(name, flags, *args, **kwargs)
        monkeypatch.setattr(adapter.os, "open", absent)
    else:
        record = json.loads(target.read_text())
        if mutation == "uncertain":
            record.update(state="uncertain", code="child_result_invalid")
        elif mutation == "profile-mismatch":
            record["profile_id"] = "00000000-0000-4000-8000-000000000099"
        elif mutation == "run-invalid":
            record["run_id"] = "not-a-uuid"
        elif mutation == "attempt-profile-invalid":
            record["profile_id"] = "not-a-uuid"
        elif mutation == "backup-identity-mismatch":
            record["backup_identity"][1] += 1
        else:
            record["schema_version"] = True
        target.write_text(json.dumps(record, sort_keys=True) + "\n")
    before = {p.name: p.read_bytes() for p in recovery.iterdir()}
    with pytest.raises(adapter.CreationError) as error, adapter._open_creation_evidence(recovery):
        pytest.fail("invalid creation evidence was accepted")
    assert error.value.code == "creation_evidence_invalid"
    assert {p.name: p.read_bytes() for p in recovery.iterdir()} == before
    assert len(calls) == 1
    writer.close()


def test_read_creation_evidence_rejects_copied_backup_path(tmp_path, monkeypatch):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    assert adapter.main(["--backup", str(recovery)]) == 0
    copied = recovery.parent / ("canary-" + "f" * 32)
    shutil.copytree(recovery, copied, copy_function=shutil.copy2)
    with pytest.raises(adapter.CreationError), adapter._open_creation_evidence(copied):
        pytest.fail("copied backup was accepted")
    linked = recovery.parent / ("canary-" + "e" * 32)
    os.symlink(recovery, linked)
    with pytest.raises(adapter.CreationError) as error, adapter._open_creation_evidence(linked):
        pytest.fail("symlinked backup was accepted")
    assert error.value.code == "creation_evidence_invalid"
    writer.close()


@pytest.mark.parametrize("mutation", ["proof-bytes", "result-schema-bool", "result-count-bool"])
def test_read_creation_evidence_rejects_copied_proof_or_strict_result_drift(
    tmp_path, monkeypatch, mutation
):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    assert adapter.main(["--backup", str(recovery)]) == 0
    if mutation == "proof-bytes":
        target = recovery / "history.json"
        target.write_bytes(target.read_bytes() + b" ")
    else:
        target = recovery / "result.json"
        result = json.loads(target.read_text())
        if mutation == "result-schema-bool":
            result["schema_version"] = True
        else:
            first = next(iter(result["record_counts"]))
            result["record_counts"][first] = bool(result["record_counts"][first])
        target.write_text(json.dumps(result, sort_keys=True) + "\n")
    with pytest.raises(adapter.CreationError), adapter._open_creation_evidence(recovery):
        pytest.fail("drifted proof/result was accepted")
    writer.close()


def test_read_creation_evidence_rejects_artifact_metadata_drift_and_closes_fds(
    tmp_path, monkeypatch
):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    assert adapter.main(["--backup", str(recovery)]) == 0
    (recovery / "history.json").chmod(0o640)
    opened = []
    original_open_chain = backup._open_chain
    original_close_all = backup._close_all
    def track_open(*args, **kwargs):
        result = original_open_chain(*args, **kwargs)
        opened.extend(result[0])
        return result
    def track_close(fds):
        original_close_all(fds)
        assert all(_fd_closed(fd) for fd in opened)
    monkeypatch.setattr(backup, "_open_chain", track_open)
    monkeypatch.setattr(backup, "_close_all", track_close)
    with pytest.raises(adapter.CreationError), adapter._open_creation_evidence(recovery):
        pytest.fail("drifted artifact was accepted")
    assert opened and all(_fd_closed(fd) for fd in opened)
    writer.close()


def _fd_closed(fd):
    try:
        os.fstat(fd)
        return False
    except OSError:
        return True


def test_same_backup_rerun_collides_before_gate_or_second_child(tmp_path, monkeypatch, capsys):
    recovery, _db, writer, gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    assert adapter.main(["--backup", str(recovery)]) == 0
    gates_before = len(gates)
    assert adapter.main(["--backup", str(recovery)]) == 1
    result = capsys.readouterr()
    assert result.out == f"CANARY_CREATION: PASS (recovery={recovery})\n"
    assert result.err == f"CANARY_CREATION: FAIL (creation_attempt_exists; recovery={recovery})\n"
    assert len(calls) == 1 and len(gates) == gates_before
    writer.close()


@pytest.mark.parametrize("outcome", ["timeout", "nonzero", "malformed"])
def test_uncertain_child_is_terminal_and_never_retried(tmp_path, monkeypatch, capsys, outcome):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls, outcome=outcome)
    assert adapter.main(["--backup", str(recovery)]) == 1
    assert capsys.readouterr().out == ""
    assert (recovery / "create-attempt.json").is_file()
    assert json.loads((recovery / "creation-outcome.json").read_text())["state"] == "uncertain"
    assert adapter.main(["--backup", str(recovery)]) == 1
    failure = capsys.readouterr()
    assert failure.out == ""
    assert failure.err == f"CANARY_CREATION: FAIL (creation_attempt_exists; recovery={recovery})\n"
    assert len(calls) == 1
    writer.close()


def _report_database_rebind(monkeypatch, db):
    original_capture = backup._capture_database_target
    active = [False]

    def capture(database_url):
        target = original_capture(database_url)
        if active[0] and target["path"] == db:
            identity = list(target["identity"])
            identity[1] += 1
            target = {**target, "identity": tuple(identity)}
        return target

    monkeypatch.setattr(backup, "_capture_database_target", capture)
    return lambda: active.__setitem__(0, True)


def test_source_proof_rebind_rejects_before_attempt_or_child(tmp_path, monkeypatch, capsys):
    recovery, db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    rebind = _report_database_rebind(monkeypatch, db)
    original_digest = adapter._sha(db.read_bytes())
    rebind()
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    monkeypatch.setattr(adapter.subprocess, "run", lambda *_args, **_kwargs: calls.append("spawn"))
    assert adapter.main(["--backup", str(recovery)]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == f"CANARY_CREATION: FAIL (source_database_changed; recovery={recovery})\n"
    assert calls == [] and not (recovery / "create-attempt.json").exists()
    assert adapter._sha(db.read_bytes()) == original_digest
    unchanged = backup.database._connect_database(f"sqlite:///{db}")
    try:
        assert len(backup.database.snapshot_history(unchanged)["runs"]) == 1
    finally:
        unchanged.close()
    writer.close()


@pytest.mark.parametrize(
    ("boundary", "target"),
    [(phase, target) for phase in ("before-child", "after-postcheck")
     for target in ("database", "environment", "policy")],
)
def test_original_source_is_rechecked_at_both_attempt_boundaries(
    tmp_path, monkeypatch, capsys, boundary, target
):
    recovery, db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    before = backup.database._connect_database(f"sqlite:///{db}")
    try:
        old_history = backup.database.snapshot_history(before)
    finally:
        before.close()
    original_digest = adapter._sha(db.read_bytes())
    source_path = db if target == "database" else (
        backup.ENV_PATH if target == "environment" else backup.POLICY_PATH
    )
    post_snapshots = []
    rebind = _report_database_rebind(monkeypatch, db) if target == "database" else None

    def drift():
        if target == "database":
            rebind()
        else:
            source_path.write_bytes(b"SYNTHETIC-CONFIG-DRIFT\\n")

    if boundary == "before-child":
        original_attempt = adapter._create_attempt

        def after_attempt(*args, **kwargs):
            result = original_attempt(*args, **kwargs)
            drift()
            return result

        monkeypatch.setattr(adapter, "_create_attempt", after_attempt)
        expected_children = 0
    else:
        original_postcheck = adapter._post_create

        def after_postcheck(connection, *args, **kwargs):
            result = original_postcheck(connection, *args, **kwargs)
            post_snapshots.append(backup.database.snapshot_history(connection))
            drift()
            return result

        monkeypatch.setattr(adapter, "_post_create", after_postcheck)
        expected_children = 1

    assert adapter.main(["--backup", str(recovery)]) == 1
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (
        "", f"CANARY_CREATION: FAIL (creation_uncertain; recovery={recovery})\n",
    )
    assert len(calls) == expected_children
    assert json.loads((recovery / "create-attempt.json").read_text())["state"] == "attempted"
    assert json.loads((recovery / "creation-outcome.json").read_text())["state"] == "uncertain"
    assert binding_tests.PROFILE_ID not in captured.out + captured.err
    if boundary == "before-child":
        if target == "database":
            assert adapter._sha(db.read_bytes()) == original_digest
        else:
            assert source_path.read_bytes() == b"SYNTHETIC-CONFIG-DRIFT\\n"
        unchanged = backup.database._connect_database(f"sqlite:///{db}")
        try:
            assert backup.database.snapshot_history(unchanged) == old_history
        finally:
            unchanged.close()
    else:
        after = post_snapshots[0]
        assert len(after["runs"]) == len(old_history["runs"]) + 1
        retained = tuple(row for row in after["runs"] if row in old_history["runs"])
        assert retained == old_history["runs"]
        assert after["batches"] == old_history["batches"]
        assert after["items"] == old_history["items"]
        if target != "database":
            assert source_path.read_bytes() == b"SYNTHETIC-CONFIG-DRIFT\\n"
    assert writer.total_changes == 0
    writer.close()


@pytest.mark.parametrize("boundary", ["before-child", "after-postcheck"])
@pytest.mark.parametrize("mutation", ["mode", "reported-inode"])
@pytest.mark.parametrize(
    "artifact",
    ["source-proof.json", "history.json", "role-radar.db", "role-radar.env",
     "discovery-policy.toml", "intent.json", "result.json"],
)
def test_retained_backup_files_are_revalidated_at_both_boundaries(
    tmp_path, monkeypatch, capsys, boundary, mutation, artifact
):
    recovery, db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    before = backup.database._connect_database(f"sqlite:///{db}")
    try:
        old_history = backup.database.snapshot_history(before)
    finally:
        before.close()
    target = recovery / artifact
    original_stat = adapter.os.stat
    child_fd = []
    active = [False]

    def drift_stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if (active[0] and path == artifact and kwargs.get("dir_fd") == child_fd[0]
                and mutation == "reported-inode"):
            values = {name: getattr(result, name) for name in dir(result)
                      if name.startswith("st_")}
            values["st_ino"] += 1
            return SimpleNamespace(**values)
        return result

    if mutation == "reported-inode":
        monkeypatch.setattr(adapter.os, "stat", drift_stat)

    def drift():
        active[0] = True
        if mutation == "mode":
            target.chmod(0o640)

    if boundary == "before-child":
        original_attempt = adapter._create_attempt

        def after_attempt(*args, **kwargs):
            child_fd.append(args[3])
            result = original_attempt(*args, **kwargs)
            drift()
            return result

        monkeypatch.setattr(adapter, "_create_attempt", after_attempt)
        expected_children = 0
    else:
        original_postcheck = adapter._post_create

        def after_postcheck(connection, *args, **kwargs):
            result = original_postcheck(connection, *args, **kwargs)
            drift()
            return result

        original_attempt = adapter._create_attempt

        def track_attempt(*args, **kwargs):
            child_fd.append(args[3])
            return original_attempt(*args, **kwargs)

        monkeypatch.setattr(adapter, "_create_attempt", track_attempt)
        monkeypatch.setattr(adapter, "_post_create", after_postcheck)
        expected_children = 1

    assert adapter.main(["--backup", str(recovery)]) == 1
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (
        "", f"CANARY_CREATION: FAIL (creation_uncertain; recovery={recovery})\n",
    )
    assert len(calls) == expected_children
    assert stat.S_IMODE(target.stat().st_mode) == (0o640 if mutation == "mode" else 0o600)
    assert json.loads((recovery / "create-attempt.json").read_text())["state"] == "attempted"
    assert json.loads((recovery / "creation-outcome.json").read_text())["state"] == "uncertain"
    assert binding_tests.PROFILE_ID not in captured.out + captured.err
    after = backup.database._connect_database(f"sqlite:///{db}")
    try:
        snapshot = backup.database.snapshot_history(after)
        assert snapshot["batches"] == old_history["batches"]
        assert snapshot["items"] == old_history["items"]
        if boundary == "before-child":
            assert snapshot == old_history
        else:
            added = [row for row in snapshot["runs"] if row not in old_history["runs"]]
            assert len(added) == 1 and added[0]["status"] == "pending"
    finally:
        after.close()
    writer.close()


def test_database_mode_weakening_after_child_is_terminally_uncertain(
    tmp_path, monkeypatch, capsys
):
    recovery, db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    calls = []
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, calls)
    original_run = adapter.subprocess.run

    def weaken_after_child(*args, **kwargs):
        result = original_run(*args, **kwargs)
        db.chmod(0o666)
        return result

    monkeypatch.setattr(adapter.subprocess, "run", weaken_after_child)
    assert adapter.main(["--backup", str(recovery)]) == 1
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (
        "", f"CANARY_CREATION: FAIL (creation_uncertain; recovery={recovery})\n",
    )
    assert stat.S_IMODE(db.stat().st_mode) == 0o666
    assert len(calls) == 1
    assert json.loads((recovery / "creation-outcome.json").read_text())["state"] == "uncertain"
    connection = backup.database._connect_database(f"sqlite:///{db}")
    try:
        assert len(backup.database.snapshot_history(connection)["runs"]) == 2
    finally:
        connection.close()
    writer.close()


def test_documented_create_module_help_needs_no_pythonpath(tmp_path):
    home, temp, cache = (tmp_path / name for name in ("home", "tmp", "cache"))
    for directory in (home, temp, cache):
        directory.mkdir()
    env = {
        "PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temp),
        "XDG_CACHE_HOME": str(cache), "UV_OFFLINE": "1",
        "ROLE_RADAR_TEST_NETWORK_DENY": "1", "NO_UPDATE_NOTIFIER": "1",
    }
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-B", "-m", "scripts.bounded_canary_create", "--help"],
        cwd=root, env=env, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "--backup" in result.stdout and result.stderr == ""
    assert "never start a worker" in result.stdout
    assert all(not any(directory.iterdir()) for directory in (home, temp, cache))


def test_creation_reader_whitelists_only_fixed_timer_receipt_slots(tmp_path, monkeypatch):
    recovery, _db, writer, _gates = _ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0)
    _simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    assert adapter.main(["--backup", str(recovery)]) == 0
    for name in ("timer-cleanup-intent.json", "timer-cleanup-outcome.json"):
        receipt = recovery / name
        receipt.write_bytes(b"not proof")
        receipt.chmod(0o600)
    with adapter._open_creation_evidence(recovery) as evidence:
        assert evidence["run_id"]
        assert not {"timer-cleanup-intent.json", "timer-cleanup-outcome.json"} \
            & evidence["artifact_identities"].keys()
    (recovery / "arbitrary-receipt.json").write_bytes(b"not allowed")
    with pytest.raises(adapter.CreationError), adapter._open_creation_evidence(recovery):
        pytest.fail("arbitrary receipt name was accepted")
    writer.close()
