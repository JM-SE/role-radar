from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess

import pytest

from scripts import bounded_canary_timers as timers
from tests.unit import test_bounded_canary_binding as binding_tests
from tests.unit import test_bounded_canary_create as create_tests
from tests.unit import test_bounded_canary_timers as timer_tests


@pytest.mark.parametrize(
    "mutation",
    ["history-bytes", "history-mode", "creation-receipt", "directory-copy",
     "ancestor-rebind", "intent-bytes"],
)
def test_proof_changed_after_intent_blocks_dispatch_and_preserves_run(
    tmp_path, monkeypatch, mutation
):
    recovery, db, writer, _gates = create_tests._ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(create_tests.adapter.os, "geteuid", lambda: 0)
    create_tests._simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert create_tests.adapter.main(["--backup", str(recovery)]) == 0

    connection = create_tests.backup.database._connect_database(f"sqlite:///{db}")
    try:
        old_history = create_tests.backup.database.snapshot_history(connection)
    finally:
        connection.close()
    old_changes = writer.total_changes
    calls = []
    after = False

    def systemctl(command, **kwargs):
        nonlocal after
        assert kwargs == {
            "capture_output": True, "text": True, "timeout": 15, "check": False,
            "shell": False, "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        }
        calls.append(command)
        if command[1] == "show":
            props = command[3].split("=", 1)[1]
            return subprocess.CompletedProcess(
                command, 0,
                timer_tests._show_output(command[4:], props, after=after), "",
            )
        assert command == ["/usr/bin/systemctl", "disable", "--now", *timers.TIMER_UNITS]
        after = True
        return subprocess.CompletedProcess(command, 0, "", "")

    write_receipt = timers._write_receipt
    injected = []

    def inject_after_intent(evidence, name, record):
        identity = write_receipt(evidence, name, record)
        if name != timers.INTENT_NAME:
            return identity
        assert json.loads((recovery / name).read_bytes())["state"] == "attempted"
        if mutation == "history-bytes":
            target = recovery / "history.json"
            target.write_bytes(target.read_bytes() + b" ")
        elif mutation == "history-mode":
            (recovery / "history.json").chmod(0o644)
        elif mutation == "creation-receipt":
            (recovery / "creation-outcome.json").write_bytes(b"{}\n")
        elif mutation == "directory-copy":
            original = recovery.with_name("held-original")
            recovery.rename(original)
            shutil.copytree(original, recovery, copy_function=shutil.copy2)
        elif mutation == "ancestor-rebind":
            parent = recovery.parent
            original = parent.with_name("held-parent")
            parent.rename(original)
            parent.mkdir(mode=0o755)
            (original / recovery.name).rename(recovery)
        else:
            (recovery / name).write_bytes(b"{}\n")
        injected.append(name)
        return identity

    monkeypatch.setattr(timers, "_write_receipt", inject_after_intent)
    output, error = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        rc = timers.main(["--backup", str(recovery)], runner=systemctl)

    dispatches = [command for command in calls if command[1] == "disable"]
    assert injected == [timers.INTENT_NAME]
    assert (rc, output.getvalue(), error.getvalue()) == (
        1, "", (
            f"CANARY_TIMER_CLEANUP: FAIL "
            f"(timer_cleanup_evidence_changed; recovery={recovery})\n"
        ),
    )
    assert dispatches == []
    assert (recovery / timers.INTENT_NAME).is_file()
    assert not (recovery / timers.OUTCOME_NAME).exists()
    assert writer.total_changes == old_changes
    connection = create_tests.backup.database._connect_database(f"sqlite:///{db}")
    try:
        assert create_tests.backup.database.snapshot_history(connection) == old_history
    finally:
        connection.close()
    writer.close()


def test_evidence_drift_during_dispatch_yields_uncertain_not_completed(
    tmp_path, monkeypatch
):
    recovery, _db, writer, _gates = create_tests._ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(create_tests.adapter.os, "geteuid", lambda: 0)
    create_tests._simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert create_tests.adapter.main(["--backup", str(recovery)]) == 0
    calls = []

    def systemctl(command, **kwargs):
        calls.append(command)
        if command[1] == "show":
            props = command[3].split("=", 1)[1]
            return subprocess.CompletedProcess(
                command, 0,
                timer_tests._show_output(
                    command[4:], props, after=command[4] in timers.TIMER_UNITS
                ),
                "",
            )
        (recovery / "history.json").write_bytes(
            (recovery / "history.json").read_bytes() + b" "
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    output, error = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        rc = timers.main(["--backup", str(recovery)], runner=systemctl)
    assert (rc, output.getvalue(), error.getvalue()) == (
        1, "", f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_uncertain; recovery={recovery})\n",
    )
    assert len([command for command in calls if command[1] == "disable"]) == 1
    assert json.loads((recovery / timers.OUTCOME_NAME).read_text())["state"] == "uncertain"
    writer.close()


def test_unmodified_evidence_and_uncertain_dispatch_controls_still_hold(
    tmp_path, monkeypatch
):
    recovery, _db, writer, _gates = create_tests._ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(create_tests.adapter.os, "geteuid", lambda: 0)
    create_tests._simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert create_tests.adapter.main(["--backup", str(recovery)]) == 0
    calls = []

    def systemctl(command, **kwargs):
        calls.append(command)
        if command[1] == "show":
            props = command[3].split("=", 1)[1]
            return subprocess.CompletedProcess(
                command, 0,
                timer_tests._show_output(command[4:], props, after=False), "",
            )
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr="SYNTHETIC_SECRET")

    output, error = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
        rc = timers.main(["--backup", str(recovery)], runner=systemctl)
    assert (rc, output.getvalue(), error.getvalue()) == (
        1, "", f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_uncertain; recovery={recovery})\n",
    )
    assert "SYNTHETIC_SECRET" not in error.getvalue()
    assert json.loads((recovery / timers.OUTCOME_NAME).read_text())["state"] == "uncertain"
    assert len([command for command in calls if command[1] == "disable"]) == 1
    writer.close()
