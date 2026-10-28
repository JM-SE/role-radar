from __future__ import annotations

import contextlib
import io
import json
import subprocess

from scripts import bounded_canary_timers as timers
from tests.unit import test_bounded_canary_binding as binding_tests
from tests.unit import test_bounded_canary_create as create_tests

SERVICES = (
    "role-radar-api.service", "llm-broker-api.service", "llm-broker-worker.service",
    "llama-server.service", "llama-swap.service",
)


def _created_backup(tmp_path, monkeypatch):
    recovery, _db, writer, _gates = create_tests._ready_backup(tmp_path, monkeypatch)
    monkeypatch.setattr(create_tests.adapter.os, "geteuid", lambda: 0)
    create_tests._simulate_runuser(monkeypatch, binding_tests.PROFILE_ID, [])
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert create_tests.adapter.main(["--backup", str(recovery)]) == 0
    return recovery, writer


def _snapshot(unit, *, after):
    if unit in SERVICES:
        return (unit, "loaded", "active", "running", "123", "enabled")
    return (unit, "loaded", "inactive", "dead", "disabled") if after else (
        unit, "loaded", "active", "waiting", "enabled"
    )


def _show_output(units, properties, *, after, drift=False):
    fields = properties.split(",")
    blocks = []
    for unit in units:
        values = _snapshot(unit, after=after)
        if drift and after and unit == "llm-broker-worker.service":
            values = (unit, "loaded", "inactive", "dead", "0", "disabled")
        blocks.append(
            "".join(f"{key}={value}\n" for key, value in zip(fields, values, strict=True))
            + "\n"
        )
    return "".join(blocks)


def test_cleanup_composes_created_evidence_and_mutates_only_exact_timers(
    tmp_path, monkeypatch, capsys
):
    recovery, writer = _created_backup(tmp_path, monkeypatch)
    calls = []
    after = False

    def systemctl(command, **kwargs):
        nonlocal after
        calls.append((command, kwargs))
        assert kwargs["shell"] is False and kwargs["check"] is False
        assert kwargs["timeout"] == 15 and kwargs["capture_output"] is True
        if command[1] == "show":
            props = command[3].split("=", 1)[1]
            units = command[4:]
            return subprocess.CompletedProcess(
                command, 0, _show_output(units, props, after=after), ""
            )
        assert command == ["/usr/bin/systemctl", "disable", "--now", *timers.TIMER_UNITS]
        after = True
        return subprocess.CompletedProcess(command, 0, "", "")

    assert timers.main(["--backup", str(recovery)], runner=systemctl) == 0
    result = capsys.readouterr()
    assert result.out == "CANARY_TIMER_CLEANUP: PASS (timers stopped and disabled)\n"
    assert result.err == ""
    dispatches = [call for call, _ in calls if call[1] != "show"]
    assert dispatches == [["/usr/bin/systemctl", "disable", "--now", *timers.TIMER_UNITS]]
    assert len([call for call, _ in calls if call[1] == "show"]) == 4
    intent = json.loads((recovery / timers.INTENT_NAME).read_text())
    outcome = json.loads((recovery / timers.OUTCOME_NAME).read_text())
    assert intent["state"] == "attempted" and intent["run_id"]
    assert intent["backup"] == str(recovery)
    assert outcome["state"] == "completed" and outcome["run_id"] == intent["run_id"]
    assert outcome["before"]["baseline"] == outcome["after"]["baseline"]
    assert all((recovery / name).stat().st_mode & 0o777 == 0o600
               for name in (timers.INTENT_NAME, timers.OUTCOME_NAME))
    assert timers.main(["--backup", str(recovery)], runner=systemctl) == 1
    failed = capsys.readouterr()
    assert failed.out == ""
    assert failed.err == f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_exists; recovery={recovery})\n"
    assert len([call for call, _ in calls if call[1] != "show"]) == 1
    assert create_tests.adapter.main(["--backup", str(recovery)]) == 1
    assert "creation_attempt_exists" in capsys.readouterr().err
    writer.close()


def test_receipt_presence_is_not_accepted_as_cleanup_proof_or_retried(
    tmp_path, monkeypatch, capsys
):
    recovery, writer = _created_backup(tmp_path, monkeypatch)
    receipt = recovery / timers.OUTCOME_NAME
    receipt.write_bytes(b"not proof")
    receipt.chmod(0o600)
    calls = []
    assert timers.main(["--backup", str(recovery)],
                       runner=lambda *a, **k: calls.append((a, k))) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == (
        f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_exists; recovery={recovery})\n"
    )
    assert calls == []
    writer.close()


def test_missing_creation_evidence_is_rejected_before_systemd_boundary(
    tmp_path, monkeypatch, capsys
):
    backups = tmp_path / "backups"
    backups.mkdir()
    monkeypatch.setattr(create_tests.adapter, "BACKUP_ROOT", backups)
    monkeypatch.setattr(create_tests.backup, "BACKUP_ROOT", backups)
    monkeypatch.setattr(timers.os, "geteuid", lambda: 0)
    candidate = backups / ("canary-" + "f" * 32)
    calls = []
    assert timers.main(["--backup", str(candidate)],
                       runner=lambda *a, **k: calls.append((a, k))) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == (
        "CANARY_TIMER_CLEANUP: FAIL "
        f"(creation_evidence_invalid; recovery={candidate})\n"
    )
    assert calls == []


def test_uncertain_dispatch_is_durable_terminal_and_never_replayed(
    tmp_path, monkeypatch, capsys
):
    recovery, writer = _created_backup(tmp_path, monkeypatch)
    calls = []
    def systemctl(command, **kwargs):
        calls.append(command)
        if command[1] == "show":
            props = command[3].split("=", 1)[1]
            return subprocess.CompletedProcess(
                command, 0, _show_output(command[4:], props, after=False), ""
            )
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr="private-systemd-detail")

    assert timers.main(["--backup", str(recovery)], runner=systemctl) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == (
        f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_uncertain; recovery={recovery})\n"
    )
    assert "private-systemd-detail" not in result.err
    outcome = json.loads((recovery / timers.OUTCOME_NAME).read_text())
    assert outcome["state"] == "uncertain"
    assert timers.main(["--backup", str(recovery)], runner=systemctl) == 1
    assert capsys.readouterr().err == (
        f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_exists; recovery={recovery})\n"
    )
    assert len([command for command in calls if command[1] != "show"]) == 1
    writer.close()


def test_baseline_drift_reports_incomplete_without_retry_or_false_success(
    tmp_path, monkeypatch, capsys
):
    recovery, writer = _created_backup(tmp_path, monkeypatch)
    after = False
    dispatches = []
    def systemctl(command, **kwargs):
        nonlocal after
        if command[1] == "show":
            props = command[3].split("=", 1)[1]
            return subprocess.CompletedProcess(command, 0, _show_output(
                command[4:], props, after=after, drift=True
            ), "")
        dispatches.append(command)
        after = True
        return subprocess.CompletedProcess(command, 0, "", "")

    assert timers.main(["--backup", str(recovery)], runner=systemctl) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == (
        f"CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_incomplete; recovery={recovery})\n"
    )
    assert len(dispatches) == 1
    assert json.loads((recovery / timers.OUTCOME_NAME).read_text())["state"] == "incomplete"
    writer.close()
