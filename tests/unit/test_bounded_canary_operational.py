"""Offline contract tests for bounded canary operational supervision.

Every effectful seam is replaced before ``supervise`` is called.  These tests
never require root, systemd, a production database, credentials, networking,
or Telegram.
"""
from __future__ import annotations

import asyncio
import json
import multiprocessing
import os
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bounded_canary_supervision as supervision

RUN_ID = "123e4567-e89b-12d3-a456-426614174000"
PROFILE_ID = "profile-synthetic"


@dataclass
class FakeAdmission:
    path: Path
    run_id: str = RUN_ID
    profile_id: str = PROFILE_ID
    writes: list[dict[str, object]] = field(default_factory=list)
    revalidation_error: Exception | None = None
    evidence: dict[str, object] = field(init=False)
    intent_digest: str = "a" * 64
    entered: bool = False
    closed: bool = False

    def __post_init__(self) -> None:
        self.evidence = {
            "backup_path": self.path,
            "backup_identity": (1, 2, 3),
            "artifact_digests": {"creation-outcome.json": "digest"},
            "run_id": self.run_id,
            "profile_id": self.profile_id,
        }

    def __enter__(self) -> FakeAdmission:
        self.entered = True
        return self

    def __exit__(self, *_exc: object) -> None:
        self.closed = True

    def _raise_if_drift(self) -> None:
        if self.revalidation_error is not None:
            raise self.revalidation_error

    def _check_anchors(self) -> None:
        self._raise_if_drift()

    def _check_retained(self) -> None:
        self._raise_if_drift()

    def _check_intent(self) -> None:
        self._raise_if_drift()

    def revalidate(self) -> FakeAdmission:
        self._raise_if_drift()
        return self

    def _write_outcome(self, record: dict[str, object]) -> None:
        self.writes.append(record)


@dataclass
class FakeClock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeRunner:
    """Synthetic subprocess.run replacement recording every command."""

    def __init__(self, *, start_returncode: int = 0, stop_returncode: int = 0,
                 stop_error: Exception | None = None) -> None:
        self.start_returncode = start_returncode
        self.stop_returncode = stop_returncode
        self.stop_error = stop_error
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(command), kwargs))
        if command[1] == "start":
            return subprocess.CompletedProcess(command, self.start_returncode, "", "")
        if command[1] == "stop":
            if self.stop_error is not None:
                raise self.stop_error
            return subprocess.CompletedProcess(command, self.stop_returncode, "", "")
        raise AssertionError(f"unexpected command: {command!r}")

    @property
    def operational_commands(self) -> list[list[str]]:
        return [command for command, _kwargs in self.calls]


class FakeChannel:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def wait_ready(self, _deadline):
        pass

    def allow(self, _deadline):
        pass


def _synthetic_channel(monkeypatch):
    monkeypatch.setattr(supervision, "_worker_identity", lambda: (1, 1))
    monkeypatch.setattr(
        supervision.fence_runtime, "canary_channel",
        lambda *_args, **_kwargs: FakeChannel(),
    )


def _setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, observations: list[dict[str, object]],
    start_returncode: int = 0, stop_returncode: int = 0,
    stop_error: Exception | None = None,
) -> tuple[FakeAdmission, FakeRunner, FakeClock]:
    admission = FakeAdmission(tmp_path / "synthetic-backup")
    runner = FakeRunner(
        start_returncode=start_returncode,
        stop_returncode=stop_returncode,
        stop_error=stop_error,
    )
    clock = FakeClock()
    _synthetic_channel(monkeypatch)
    monkeypatch.setattr(supervision, "_bounded", lambda fn, _deadline: fn())
    monkeypatch.setattr(supervision, "admit", lambda _path: admission)
    monkeypatch.setattr(supervision.preflight, "run_gate", lambda run_id, runner=None: None)
    monkeypatch.setattr(supervision, "_require_api_fence", lambda *_args: None)
    monkeypatch.setattr(
        supervision.preflight, "_show",
        lambda units, _properties, _runner=None: {
            units[0]: {"Id": units[0], "LoadState": "loaded", "TimeoutStartUSec": "600s"}
        },
    )
    sequence = iter(observations)

    def read_observation(
        _evidence: object,
        _runner: object,
        _clock: object = None,
        _deadline: object = None,
    ) -> dict[str, object]:
        try:
            return next(sequence)
        except StopIteration:
            return observations[-1]

    monkeypatch.setattr(supervision, "_read_observation", read_observation)
    return admission, runner, clock


def _unit_commands(runner: FakeRunner) -> list[list[str]]:
    return [command for command in runner.operational_commands
            if len(command) >= 3 and command[1] in {"start", "stop"}]


def _assert_receipt(record: dict[str, object], state: str) -> None:
    assert record["state"] == state
    assert record["result"] == {"state": state}
    assert record["run_id"] == RUN_ID
    assert record["profile_id"] == PROFILE_ID
    assert record["notification_mode"] == "none"
    assert supervision.receipt_valid(record, {
        "backup_path": Path(record["backup"]),
        "backup_identity": tuple(record["backup_identity"]),
        "artifact_digests": {"creation-outcome.json": "digest"},
        "run_id": RUN_ID,
        "profile_id": PROFILE_ID,
    }, outcome=True)


def test_completed_starts_once_and_uses_exact_uuid_instance(tmp_path, monkeypatch):
    admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "complete", "released": True}]
    )
    run_gate_calls: list[str] = []
    monkeypatch.setattr(
        supervision.preflight, "run_gate",
        lambda run_id, runner=None: run_gate_calls.append(run_id),
    )

    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    expected = f"role-radar-canary-worker@{RUN_ID}.service"
    assert _unit_commands(runner) == [["/usr/bin/systemctl", "start", "--no-block", expected]]
    assert run_gate_calls == [RUN_ID]
    assert admission.entered and admission.closed
    assert len(admission.writes) == 1
    _assert_receipt(record, "completed")


@pytest.mark.parametrize("value", [
    "infinity", "0", "601s", "invalid", "600s 1us",
    "600s 0.00000000000000000000000000001us",
])
def test_unsafe_exact_instance_timeout_prevents_start(tmp_path, monkeypatch, value):
    _admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "complete", "released": True}]
    )
    def show(units, _properties, _runner=None):
        unit = units[0]
        return {unit: {"Id": unit, "LoadState": "loaded", "TimeoutStartUSec": value}}
    monkeypatch.setattr(supervision.preflight, "_show", show)
    with pytest.raises(supervision.SupervisionError) as error:
        supervision.supervise(
            tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
        )
    assert error.value.code == "supervision_runtime_cap_invalid"
    assert _unit_commands(runner) == []


@pytest.mark.parametrize("value", ["10min", "600000000", "599.5s", "1us", "9min 59s"])
def test_safe_exact_instance_timeout_allows_start(tmp_path, monkeypatch, value):
    _admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "complete", "released": True}]
    )
    def show(units, _properties, _runner=None):
        unit = units[0]
        return {unit: {"Id": unit, "LoadState": "loaded", "TimeoutStartUSec": value}}
    monkeypatch.setattr(supervision.preflight, "_show", show)
    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )
    assert record["state"] == "completed"
    assert [command[1] for command in _unit_commands(runner)] == ["start"]


def test_blocked_observation_does_not_hold_supervisor_past_deadline(monkeypatch):
    def blocked(*_args):
        time.sleep(1)
        return {"decision": "complete", "released": True}
    monkeypatch.setattr(supervision, "_read_observation", blocked)
    started = time.monotonic()
    state, _ = supervision._observe_until(
        {}, None, time.monotonic, time.sleep, started + 0.1
    )
    assert state in {"timeout", "uncertain"}
    assert time.monotonic() - started < 0.6


def test_blocked_post_stop_evidence_does_not_hold_supervisor(monkeypatch, tmp_path):
    marker = tmp_path / "stop-dispatched"
    admission = FakeAdmission(tmp_path)
    def runner(command, **_kwargs):
        assert command[1] == "stop"
        marker.write_text("stopped")
        return subprocess.CompletedProcess(command, 0)
    def blocked(_admission):
        time.sleep(1)
    monkeypatch.setattr(supervision, "STOP_SECONDS", 0.1)
    monkeypatch.setattr(supervision, "_safe_revalidate", blocked)
    started = time.monotonic()
    state = supervision._stop_exact(
        admission, {"run_id": RUN_ID}, runner, time.monotonic, time.sleep, False
    )
    assert marker.read_text() == "stopped"
    assert state == "uncertain"
    assert time.monotonic() - started < 0.6


def test_blocked_outcome_write_never_returns_completed(monkeypatch, tmp_path):
    admission = FakeAdmission(tmp_path)
    _synthetic_channel(monkeypatch)
    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0)
    def blocked(_record):
        time.sleep(1)
    admission._write_outcome = blocked
    monkeypatch.setattr(supervision, "admit", lambda _path: admission)
    monkeypatch.setattr(supervision, "OBSERVATION_SECONDS", 0.15)
    monkeypatch.setattr(supervision.preflight, "run_gate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(supervision, "_require_runtime_cap", lambda *_args: None)
    monkeypatch.setattr(supervision, "_require_api_fence", lambda *_args: None)
    monkeypatch.setattr(
        supervision, "_read_observation",
        lambda *_args: {"decision": "complete", "released": True},
    )
    started = time.monotonic()
    with pytest.raises(supervision.SupervisionError) as error:
        supervision.supervise(tmp_path / "synthetic-backup", runner=runner)
    assert error.value.code == "supervision_outcome_uncertain"
    assert time.monotonic() - started < 0.8


def test_late_completed_observation_does_not_claim_completion(tmp_path, monkeypatch):
    _admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "complete", "released": True}]
    )
    def slow_read(_evidence, _runner, _clock=None, _deadline=None):
        clock.now += supervision.OBSERVATION_SECONDS + 1
        return {"decision": "complete", "released": True}
    monkeypatch.setattr(supervision, "_read_observation", slow_read)
    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )
    assert record["state"] != "completed"
    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]


def test_observation_timeout_dispatches_one_exact_stop(tmp_path, monkeypatch):
    admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "wait", "released": False}]
    )
    def timeout_then_quiescent(_evidence, _runner, observation_clock=None, _deadline=None):
        if observation_clock is not None and observation_clock() >= supervision.OBSERVATION_SECONDS:
            return {"decision": "incomplete", "released": True}
        return {"decision": "wait", "released": False}
    monkeypatch.setattr(supervision, "_read_observation", timeout_then_quiescent)
    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    expected = f"role-radar-canary-worker@{RUN_ID}.service"
    assert _unit_commands(runner) == [
        ["/usr/bin/systemctl", "start", "--no-block", expected],
        ["/usr/bin/systemctl", "stop", expected],
    ]
    assert clock.now <= supervision.OBSERVATION_SECONDS + supervision.STOP_SECONDS
    assert admission.writes[0]["result"] == {"state": "incomplete"}
    _assert_receipt(record, "incomplete")


def test_stop_does_not_wait_for_slow_evidence_revalidation(tmp_path, monkeypatch):
    admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "wait", "released": False}]
    )
    def slow_evidence():
        clock.now += supervision.STOP_SECONDS + 1
    admission._check_retained = slow_evidence
    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )
    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
    assert record["state"] == "uncertain"


def test_start_failure_preserves_uncertainty_after_quiescent_stop(tmp_path, monkeypatch):
    admission, runner, clock = _setup(
        monkeypatch,
        tmp_path,
        observations=[{"decision": "incomplete", "released": True}],
        start_returncode=1,
    )

    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    assert len(_unit_commands(runner)) == 2
    assert _unit_commands(runner)[0][1] == "start"
    assert _unit_commands(runner)[1][1] == "stop"
    assert admission.writes[0]["result"] == {"state": "uncertain"}
    _assert_receipt(record, "uncertain")


def test_changed_evidence_after_fence_ready_never_authorizes_worker(tmp_path, monkeypatch):
    admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "incomplete", "released": True}]
    )
    checks = 0

    def revalidate():
        nonlocal checks
        checks += 1
        if checks == 3:
            raise supervision.SupervisionError("supervision_evidence_changed")
        return admission

    class Channel(FakeChannel):
        def allow(self, _deadline):
            pytest.fail("worker authorized after evidence changed")

    admission.revalidate = revalidate
    monkeypatch.setattr(
        supervision.fence_runtime, "canary_channel", lambda *_args, **_kwargs: Channel()
    )
    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )
    assert checks == 3
    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
    assert record["state"] == "uncertain"

@pytest.mark.parametrize("failure_check", [1, 2])
def test_api_fence_failure_never_authorizes_worker(tmp_path, monkeypatch, failure_check):
    _admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "incomplete", "released": True}]
    )
    checks = 0

    def check_api(*_args):
        nonlocal checks
        checks += 1
        if checks == failure_check:
            raise supervision.SupervisionError("supervision_api_fence_uncertain")

    class Channel(FakeChannel):
        def allow(self, _deadline):
            pytest.fail("worker authorized without API fence")

    monkeypatch.setattr(supervision, "_require_api_fence", check_api)
    monkeypatch.setattr(
        supervision.fence_runtime, "canary_channel", lambda *_args, **_kwargs: Channel()
    )
    if failure_check == 1:
        with pytest.raises(supervision.SupervisionError, match="supervision_api_fence_uncertain"):
            supervision.supervise(
                tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
            )
        assert _unit_commands(runner) == []
    else:
        record = supervision.supervise(
            tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
        )
        assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
        assert record["state"] == "uncertain"



@pytest.mark.parametrize("stop_mode", ["failed", "timeout"])
def test_stop_failure_or_timeout_is_uncertain(tmp_path, monkeypatch, stop_mode):
    runner_kwargs: dict[str, object]
    if stop_mode == "failed":
        runner_kwargs = {"stop_returncode": 1}
    else:
        runner_kwargs = {"stop_error": TimeoutError("synthetic timeout")}
    admission, runner, clock = _setup(
        monkeypatch,
        tmp_path,
        observations=[{"decision": "wait", "released": False}],
        **runner_kwargs,
    )

    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
    assert admission.writes[0]["result"] == {"state": "uncertain"}
    _assert_receipt(record, "uncertain")


def test_pid_zero_does_not_imply_released_lease(tmp_path, monkeypatch):
    admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "complete", "released": False}]
    )
    # This synthetic observation is the classifier's PID=0/quiescent case with
    # ownership retained; the public supervisor must not infer lease release.

    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
    assert admission.writes[0]["result"] == {"state": "uncertain"}
    _assert_receipt(record, "uncertain")


def test_observation_uncertainty_stops_once_without_leaking_database_details(tmp_path, monkeypatch):
    _admission, runner, clock = _setup(
        monkeypatch,
        tmp_path,
        observations=[{"decision": "uncertain", "released": False}],
    )

    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
    assert "database" not in repr(record).lower()
    _assert_receipt(record, "uncertain")


def test_source_or_profile_drift_prevents_start(tmp_path, monkeypatch):
    drift = supervision.SupervisionError("supervision_evidence_changed")
    admission, runner, clock = _setup(
        monkeypatch, tmp_path, observations=[{"decision": "complete", "released": True}]
    )
    admission.revalidation_error = drift

    with pytest.raises(supervision.SupervisionError) as error:
        supervision.supervise(
            tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
        )

    assert error.value.code == "supervision_evidence_changed"
    assert _unit_commands(runner) == []
    assert admission.writes == []



@pytest.mark.parametrize(
    "failure_code",
    ["supervision_history_changed", "supervision_observation_timeout"],
)
def test_postflight_history_or_database_timeout_is_uncertain(
    tmp_path, monkeypatch, failure_code
):
    real_read_observation = supervision._read_observation
    admission, runner, clock = _setup(
        monkeypatch,
        tmp_path,
        observations=[{"decision": "wait", "released": False}],
    )
    monkeypatch.setattr(supervision, "_read_observation", real_read_observation)
    observations = 0

    def show(units, _properties, _runner=None):
        unit = units[0]
        return {
            unit: {
                "Id": unit,
                "LoadState": "loaded",
                "TimeoutStartUSec": "600s",
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": "0",
            }
        }

    def read_run(_evidence, _clock=None, _deadline=None):
        nonlocal observations
        observations += 1
        if observations == 1:
            return "pending", False
        raise supervision.SupervisionError(failure_code)

    monkeypatch.setattr(supervision.preflight, "_show", show)
    monkeypatch.setattr(supervision, "_read_run_observation", read_run)

    record = supervision.supervise(
        tmp_path / "synthetic-backup", runner=runner, monotonic=clock, sleep=clock.sleep
    )

    assert [command[1] for command in _unit_commands(runner)] == ["start", "stop"]
    assert admission.writes[0]["result"] == {"state": "uncertain"}
    assert failure_code not in repr(record)
    _assert_receipt(record, "uncertain")


def test_real_admission_fence_handshake_and_postflight_reject_replay(
    tmp_path, monkeypatch, synthetic_fence
):
    from role_radar.api import fence_attestation as api_server
    from tests.unit.test_bounded_canary_supervision import _created, _snapshot

    runtime = supervision.fence_runtime
    recovery, db, writer = _created(tmp_path, monkeypatch)
    before = _snapshot(db)
    run_id = json.loads((recovery / "creation-outcome.json").read_text())["run_id"]
    commands = tmp_path / "synthetic-commands"
    done = tmp_path / "worker-finished"
    monkeypatch.setattr(runtime, "_read_cgroup_path", lambda _pid: (
        f"/system.slice/role-radar-canary-worker@{run_id}.service",
    ))
    monkeypatch.setattr(supervision, "_worker_identity", lambda: (os.getuid(), os.getgid()))
    monkeypatch.setattr(supervision, "OBSERVATION_SECONDS", 5)
    monkeypatch.setattr(supervision, "STOP_SECONDS", 1)
    monkeypatch.setattr(supervision, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(
        supervision.api_attestation, "API_RUNTIME_DIR", str(synthetic_fence / "api")
    )
    monkeypatch.setattr(
        supervision.api_attestation, "_read_cgroup_path",
        lambda _pid: (supervision.api_attestation.API_CGROUP_PATH,),
    )
    monkeypatch.setattr(
        supervision.pwd, "getpwnam", lambda _name: SimpleNamespace(
            pw_uid=os.getuid(), pw_gid=os.getgid()
        )
    )
    monkeypatch.setattr(
        supervision.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=os.getgid())
    )
    context = multiprocessing.get_context("fork")
    api_stop = context.Event()

    def api_process_main():
        async def serve():
            server = await api_server.FenceAttestationServer.start()
            try:
                await asyncio.to_thread(api_stop.wait)
            finally:
                await server.close()
        asyncio.run(serve())

    api_process = context.Process(target=api_process_main)
    api_process.start()


    def worker():
        deadline = time.monotonic() + 4
        while not commands.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        with runtime.worker_guard(run_id):
            with pytest.raises(runtime.FenceError), runtime.producer_guard():
                pytest.fail("producer entered while canary held the fence")
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "UPDATE job_search_runs SET status='completed' WHERE id=?", (run_id,)
                )
        done.write_text("finished")

    def runner(command, **_kwargs):
        with commands.open("a") as output:
            output.write(command[1] + "\n")
        assert command[1:3] == ["start", "--no-block"]
        return subprocess.CompletedProcess(command, 0, "", "")

    def show(units, _properties, _runner=None):
        unit = units[0]
        if unit == "role-radar-api.service":
            return {unit: {"Id": unit, "LoadState": "loaded", "ActiveState": "active",
                           "MainPID": str(api_process.pid)}}
        return {unit: {"Id": unit, "LoadState": "loaded",
                       "ActiveState": "inactive" if done.exists() else "active",
                       "SubState": "dead" if done.exists() else "running",
                       "MainPID": "0", "TimeoutStartUSec": "600s"}}

    monkeypatch.setattr(supervision.preflight, "run_gate", lambda _id, runner=None: None)
    monkeypatch.setattr(supervision.preflight, "_show", show)
    process = context.Process(target=worker)
    try:
        socket_path = synthetic_fence / "api" / f"ready-{api_process.pid}.sock"
        ready_deadline = time.monotonic() + 3
        while (
            not socket_path.exists() and api_process.is_alive()
            and time.monotonic() < ready_deadline
        ):
            time.sleep(0.01)
        assert socket_path.exists()
        process.start()
        record = supervision.supervise(recovery, runner=runner)
        process.join(timeout=3)
        assert process.exitcode == 0
        assert record["state"] == "completed"
        after = _snapshot(db)
        assert after["batches"] == before["batches"]
        assert after["items"] == before["items"]
        assert commands.read_text().splitlines() == ["start"]
        with pytest.raises(supervision.SupervisionError):
            supervision.supervise(recovery, runner=runner)
        assert commands.read_text().splitlines() == ["start"]
    finally:
        api_stop.set()
        api_process.join(timeout=3)
        if api_process.is_alive():
            api_process.terminate()
            api_process.join(timeout=3)
        if process.is_alive():
            process.terminate()
            process.join(timeout=3)
        writer.close()
