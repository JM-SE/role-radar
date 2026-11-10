"""Durable admission and bounded, no-notifications canary supervision.

All operational effects are deliberately narrow: one exact systemd instance,
one start dispatch, and at most one bounded stop dispatch.  Observation is
read-only and never sends or mutates delivery state.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import itertools
import json
import os
import pwd
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import ExitStack
from fractions import Fraction
from pathlib import Path

from role_radar import fence_runtime
from scripts import bounded_canary_api_attestation as api_attestation
from scripts import bounded_canary_artifacts as artifacts
from scripts import bounded_canary_backup as backup
from scripts import bounded_canary_bounded_io as bounded_io
from scripts import bounded_canary_create as creation
from scripts import bounded_canary_database as database
from scripts import bounded_canary_preflight as preflight
from scripts.canary_supervisor import classify_observation

INTENT_NAME = "supervision-intent.json"
OUTCOME_NAME = "supervision-outcome.json"
RECEIPT_VERSION = 1
OBSERVATION_SECONDS = 600.0
STOP_SECONDS = 90.0
POLL_SECONDS = 1.0
_CANARY_PROPERTIES = "Id,LoadState,ActiveState,SubState,MainPID"

class SupervisionError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _run(connection, run_id):
    rows = tuple(connection.execute(
        "SELECT id, status, profile_id, started_at, completed_at, claimed_by, "
        "lease_expires_at, canary_budget_json, canary_checkpoint_json, "
        "notification_mode, discovery_mode FROM job_search_runs WHERE id=?", (run_id,),
    ).fetchall())
    if len(rows) != 1:
        raise SupervisionError("supervision_run_invalid")
    return rows[0]


def _validate_live(evidence):
    connection = None
    saved = None
    try:
        url = "sqlite:////" + str(creation.DATABASE_PATH).lstrip("/")
        connection = database._connect_database(url)
        saved = sqlite3.connect(
            f"file:/proc/self/fd/{evidence['child_fd']}/role-radar.db?mode=ro&immutable=1",
            uri=True,
        )
        for table in ("sources", "candidate_profiles"):
            current = connection.execute(f"SELECT * FROM {table} ORDER BY id")
            original = saved.execute(f"SELECT * FROM {table} ORDER BY id")
            if current.description != original.description or any(
                left != right for left, right in itertools.zip_longest(current, original)
            ):
                raise SupervisionError("supervision_source_changed")
        history = database.snapshot_history(connection)
        before = evidence["history"]
        if (history["batches"] != tuple(before["batches"])
                or history["items"] != tuple(before["items"])):
            raise SupervisionError("supervision_history_changed")
        rows = _run(connection, evidence["run_id"])
        # Exactly the backup history plus this one newly-created pending run.
        old_ids = {item["id"] for item in before["runs"]}
        added = [item for item in history["runs"] if item["id"] not in old_ids]
        if (len(added) != 1 or added[0]["id"] != evidence["run_id"]
                or tuple(item for item in history["runs"] if item["id"] in old_ids)
                != tuple(before["runs"])):
            raise SupervisionError("supervision_history_changed")
        (run_id, status, profile_id, started, completed, claimed, lease,
         budget_raw, checkpoint_raw, notification, discovery) = rows
        from role_radar.domain.enums import NotificationMode
        from role_radar.execution_budget import CANARY_BUDGET
        budget = creation._json(budget_raw.encode() if type(budget_raw) is str else budget_raw)
        checkpoint = creation._json(
            checkpoint_raw.encode() if type(checkpoint_raw) is str else checkpoint_raw
        )
        if (run_id != evidence["run_id"] or status != "pending"
                or profile_id != evidence["profile_id"] or started is not None
                or completed is not None or claimed is not None or lease is not None
                or budget != CANARY_BUDGET
                or checkpoint != {"version": 1, "stage": "discovery", "cursor": 0,
                                  "counts": {}, "reservations": [],
                                  "logical_reservations": []}
                or notification != NotificationMode.NONE.value or discovery != "scheduled_due"):
            raise SupervisionError("supervision_run_invalid")
    except SupervisionError:
        raise
    except Exception as exc:
        raise SupervisionError("supervision_database_unavailable") from exc
    finally:
        if connection is not None:
            connection.close()
        if saved is not None:
            saved.close()


class Admission:
    """Permission context retaining the protected creation descriptors."""

    def __init__(self, path: Path):
        self.path = path
        self.stack = ExitStack()
        self.evidence = None
        self.closed = False
        self.intent_digest = None
        try:
            self.evidence = self.stack.enter_context(creation._open_creation_evidence(
                path, allow_consumed_supervision=True
            ))
            if path != self.evidence["backup_path"]:
                raise SupervisionError("creation_evidence_invalid")
            if {INTENT_NAME, OUTCOME_NAME} & set(os.listdir(self.evidence["child_fd"])):
                raise SupervisionError("supervision_intent_exists")
            self._check_anchors()
            self._check_live()
            evidence_digest = hashlib.sha256(json.dumps(
                self.evidence["artifact_digests"], sort_keys=True, separators=(",", ":")
            ).encode()).hexdigest()
            record = {
                "schema_version": RECEIPT_VERSION, "state": "attempted",
                "backup": str(path), "backup_identity": list(self.evidence["backup_identity"]),
                "creation_evidence_sha256": evidence_digest,
                "run_id": self.evidence["run_id"], "profile_id": self.evidence["profile_id"],
                "notification_mode": "none",
            }
            data = (json.dumps(record, sort_keys=True) + "\n").encode()
            self.intent_digest = hashlib.sha256(data).hexdigest()
            self.intent_data = data
            self.intent_identity = self._write_intent(data)
            try:
                self._check_anchors()
                self._check_intent()
                self._check_live()
                self._check_retained()
            except Exception:
                raise SupervisionError("supervision_admission_uncertain") from None
        except (SupervisionError, creation.CreationError) as exc:
            self.close()
            if isinstance(exc, creation.CreationError):
                raise SupervisionError("creation_evidence_invalid") from None
            raise
        except Exception:
            self.close()
            raise SupervisionError("supervision_admission_uncertain") from None

    def _check_anchors(self):
        e = self.evidence
        creation._validate_backup_anchors(
            e["root_fds"], e["root_ids"], e["root_fd"], e["child_fd"],
            e["backup_identity"], self.path.name,
        )

    def _check_retained(self):
        e = self.evidence
        creation._validate_retained_backup(
            e["child_fd"], e["artifact_identities"], e["artifact_digests"]
        )

    def _check_live(self):
        creation._current_source_after_dispatch(self.evidence["source_proof"])
        _validate_live(self.evidence)
        creation._current_source_after_dispatch(self.evidence["source_proof"])

    def _write_intent(self, data):
        e = self.evidence
        def validate():
            self._check_anchors()
            self._check_retained()
        try:
            identity = artifacts.write_new_at(
                e["child_fd"], INTENT_NAME, data, uid=0, gid=0, mode=0o600,
                chown=backup._chown_new,
                require_owner=lambda info, uid, gid: backup._require_owner(
                    info, uid, gid, "artifact_owner_invalid"),
                validate_parent=validate,
            )
            os.fsync(e["child_fd"])
            os.fsync(e["root_fd"])
            return identity
        except Exception:
            raise SupervisionError("supervision_admission_uncertain") from None

    def _check_intent(self):
        try:
            data, identity, digest = creation._read_at(
                self.evidence["child_fd"], INTENT_NAME
            )
            if (data != self.intent_data or identity[:2] != self.intent_identity
                    or digest != self.intent_digest):
                raise ValueError
        except Exception:
            raise SupervisionError("supervision_evidence_changed") from None

    def revalidate(self):
        """Recheck retained evidence and live pending/no-send state before an effect."""
        if self.closed:
            raise SupervisionError("supervision_admission_closed")
        try:
            self._check_anchors()
            self._check_retained()
            self._check_live()
            self._check_intent()
        except SupervisionError:
            raise
        except Exception:
            raise SupervisionError("supervision_evidence_changed") from None
        return self

    def _write_outcome(self, record):
        e = self.evidence
        data = (json.dumps(record, sort_keys=True) + "\n").encode()
        def validate():
            self._check_anchors()
            self._check_retained()
            self._check_intent()
        try:
            identity = artifacts.write_new_at(
                e["child_fd"], OUTCOME_NAME, data, uid=0, gid=0, mode=0o600,
                chown=backup._chown_new,
                require_owner=lambda info, uid, gid: backup._require_owner(
                    info, uid, gid, "artifact_owner_invalid"),
                validate_parent=validate,
            )
            os.fsync(e["child_fd"])
            os.fsync(e["root_fd"])
            validate()
            return identity
        except Exception:
            raise SupervisionError("supervision_outcome_uncertain") from None

    def close(self):
        if not self.closed:
            self.closed = True
            self.stack.close()

    def __enter__(self):
        if self.closed:
            raise SupervisionError("supervision_admission_closed")
        return self

    def __exit__(self, *_exc):
        self.close()


def admit(path: Path) -> Admission:
    """Exclusively persist one-start intent and return retained permission context."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SupervisionError("operator_privilege_required")
    if not isinstance(path, Path) or not path.is_absolute():
        raise SupervisionError("arguments_invalid")
    try:
        return Admission(path)
    except creation.CreationError:
        raise SupervisionError("creation_evidence_invalid") from None


def receipt_valid(record, evidence, *, outcome=False):
    """Strict reader-side validation for the fixed supervision receipt slots."""
    if type(record) is not dict:
        return False
    expected = {"schema_version", "state", "backup", "backup_identity",
                "creation_evidence_sha256", "run_id", "profile_id", "notification_mode"}
    if outcome:
        expected |= {"intent_sha256", "result"}
    return (
        set(record) == expected and type(record.get("schema_version")) is int
        and record["schema_version"] == RECEIPT_VERSION
        and ((not outcome and record.get("state") == "attempted")
             or (outcome and record.get("state") in {"completed", "incomplete", "uncertain"}))
        and record.get("backup") == str(evidence["backup_path"])
        and record.get("backup_identity") == list(evidence["backup_identity"])
        and record.get("creation_evidence_sha256") == hashlib.sha256(json.dumps(
            evidence["artifact_digests"], sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()
        and record.get("run_id") == evidence["run_id"]
        and record.get("profile_id") == evidence["profile_id"]
        and record.get("notification_mode") == "none"
        and (not outcome or (
            type(record.get("intent_sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", record["intent_sha256"])
            and type(record.get("result")) is dict
            and set(record["result"]) == {"state"}
            and record["result"]["state"] == record["state"]
        ))
    )

class _DeadlineRunner:
    """Pass every child process the smaller of its own and global deadline."""

    def __init__(self, runner, clock, deadline):
        self.runner = runner or subprocess.run
        self.clock = clock
        self.deadline = deadline

    def __call__(self, command, **kwargs):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError
        requested = kwargs.get("timeout")
        if requested is None:
            kwargs["timeout"] = remaining
        else:
            kwargs["timeout"] = min(float(requested), remaining)
        result = self.runner(command, **kwargs)
        if self.clock() > self.deadline:
            raise TimeoutError
        return result



def _bounded(fn, deadline):
    def invoke():
        try:
            return {"ok": True, "value": fn()}
        except SupervisionError as exc:
            return {"ok": False, "code": exc.code}

    result = bounded_io.call_bounded(invoke, deadline=deadline)
    if not isinstance(result, dict) or type(result.get("ok")) is not bool:
        raise bounded_io.BoundedIOError("result_invalid")
    if result["ok"] and set(result) == {"ok", "value"}:
        return result["value"]
    code = result.get("code")
    if (set(result) == {"ok", "code"} and isinstance(code, str)
            and re.fullmatch(r"supervision_[a-z_]{1,64}", code)):
        raise SupervisionError(code)
    raise bounded_io.BoundedIOError("result_invalid")

def _unit(run_id: str) -> str:
    if not isinstance(run_id, str) or not preflight.RUN_ID.fullmatch(run_id):
        raise SupervisionError("supervision_run_invalid")
    return f"{preflight.CANARY_PREFIX}{run_id}.service"


def _require_runtime_cap(unit, runner):
    """Require the exact instance's finite effective start timeout, at most 600 s."""
    try:
        records = preflight._show((unit,), "Id,LoadState,TimeoutStartUSec", runner)
        record = records[unit]
        value = record["TimeoutStartUSec"]
        if (set(records) != {unit} or record["Id"] != unit
                or record["LoadState"] != "loaded" or len(value) > 128):
            raise ValueError
        units = {
            "usec": 1, "us": 1, "msec": 1000, "ms": 1000,
            "sec": 1000000, "s": 1000000, "min": 60000000,
            "h": 3600000000, "d": 86400000000, "w": 604800000000,
        }
        if re.fullmatch(r"[0-9]+", value):
            usec = Fraction(value)
        else:
            tokens = list(re.finditer(
                r"([0-9]+(?:\.[0-9]+)?)(usec|us|msec|ms|sec|min|s|h|d|w)", value
            ))
            if not tokens or "".join(t.group(0) for t in tokens) != "".join(value.split()):
                raise ValueError
            usec = sum(Fraction(t.group(1)) * units[t.group(2)] for t in tokens)
        if not 0 < usec <= 600000000:
            raise ValueError
    except (KeyError, TypeError, ValueError, ZeroDivisionError, preflight.GateError):
        raise SupervisionError("supervision_runtime_cap_invalid") from None


def _read_run_observation(evidence, clock=None, deadline=None):
    """Read bounded metadata only; ownership is retained as a boolean."""
    if deadline is not None and deadline - clock() <= 1.0:
        raise SupervisionError("supervision_observation_timeout")
    connection = None
    try:
        url = "sqlite:////" + str(creation.DATABASE_PATH).lstrip("/")
        connection = database._connect_database(url)
        history = database.snapshot_history(connection)
        before = evidence["history"]
        if (history["batches"] != tuple(before["batches"])
                or history["items"] != tuple(before["items"])):
            raise SupervisionError("supervision_history_changed")
        old_ids = {item["id"] for item in before["runs"]}
        added = [item for item in history["runs"] if item["id"] not in old_ids]
        if (len(added) != 1 or added[0]["id"] != evidence["run_id"]
                or tuple(item for item in history["runs"] if item["id"] in old_ids)
                != tuple(before["runs"])):
            raise SupervisionError("supervision_history_changed")
        mode_rows = tuple(connection.execute(
            "SELECT notification_mode FROM job_search_runs WHERE id=?",
            (evidence["run_id"],),
        ).fetchall())
        if mode_rows != (("none",),):
            raise SupervisionError("supervision_run_invalid")
        row = added[0]
        status = row["status"]
        if not isinstance(status, str):
            raise SupervisionError("supervision_database_unavailable")
        owned = row["claimed_by"] is not None or row["lease_expires_at"] is not None
        return status, owned
    except SupervisionError:
        raise
    except Exception:
        raise SupervisionError("supervision_database_unavailable") from None
    finally:
        if connection is not None:
            connection.close()


def _read_observation(evidence, runner, clock=None, deadline=None):
    unit = _unit(evidence["run_id"])
    try:
        records = preflight._show((unit,), _CANARY_PROPERTIES, runner)
        record = records.get(unit)
        if set(records) != {unit} or record is None:
            raise ValueError
        if record.get("Id") != unit or record.get("LoadState") != "loaded":
            raise ValueError
        pid = record.get("MainPID")
        if not preflight._canonical_pid(pid):
            raise ValueError
        status, owned = _read_run_observation(evidence, clock, deadline)
        decision = classify_observation(status, record["ActiveState"], int(pid))
        if decision == "error":
            raise ValueError
        return {
            "decision": decision,
            "released": decision != "running" and not owned,
        }
    except SupervisionError:
        raise
    except Exception:
        raise SupervisionError("supervision_observation_uncertain") from None


def _observe_until(evidence, runner, clock, sleeper, deadline):
    while clock() < deadline:
        try:
            observation = _bounded(
                lambda: _read_observation(evidence, runner, clock, deadline), deadline
            )
        except (SupervisionError, bounded_io.BoundedIOError):
            return "uncertain", None
        if clock() >= deadline:
            return "timeout", None
        if observation["decision"] == "complete":
            if observation["released"]:
                return "completed", observation
            return "uncertain", observation
        if observation["decision"] == "incomplete":
            if observation["released"]:
                return "incomplete", observation
            return "uncertain", observation
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleeper(min(POLL_SECONDS, remaining))
    return "timeout", None


def _safe_revalidate(permission):
    try:
        permission._check_anchors()
        permission._check_retained()
        permission._check_intent()
    except SupervisionError:
        raise
    except Exception:
        raise SupervisionError("supervision_evidence_changed") from None


def _dispatch(runner, action, unit, timeout):
    if timeout <= 0:
        raise TimeoutError
    command = ["/usr/bin/systemctl", action]
    if action == "start":
        command.append("--no-block")
    command.append(unit)
    return runner(
        command,
        capture_output=True, text=True, timeout=timeout, check=False,
        shell=False, env=dict(preflight.CLEAN_ENV),
    )


def _worker_identity():
    try:
        account = pwd.getpwnam("role-radar")
        if account.pw_uid <= 0 or account.pw_gid <= 0:
            raise ValueError
        return account.pw_uid, account.pw_gid
    except (KeyError, ValueError, OSError):
        raise SupervisionError("supervision_gate_uncertain") from None


def _require_api_fence(runner, deadline):
    unit = "role-radar-api.service"
    try:
        account = pwd.getpwnam("role-radar")
        gid = grp.getgrnam("role-radar").gr_gid
        records = preflight._show(
            (unit,), "Id,LoadState,ActiveState,MainPID", runner
        )
        record = records[unit]
        pid_text = record["MainPID"]
        if (set(records) != {unit} or record["Id"] != unit
                or record["LoadState"] != "loaded" or record["ActiveState"] != "active"
                or not isinstance(pid_text, str) or not pid_text.isascii()
                or not pid_text.isdecimal()):
            raise ValueError
        api_attestation.verify_api_fence(
            pid=int(pid_text), uid=account.pw_uid, gid=gid, deadline=deadline
        )
    except (KeyError, ValueError, OSError, preflight.GateError, api_attestation.ApiFenceError):
        raise SupervisionError("supervision_api_fence_uncertain") from None


def _stop_exact(
    permission, evidence, runner, clock, sleeper, start_uncertain,
    preserve_uncertain=False, *, stop_deadline=None,
):
    if stop_deadline is None:
        stop_deadline = clock() + STOP_SECONDS
    stop_runner = _DeadlineRunner(runner, clock, stop_deadline)
    try:
        result = _bounded(
            lambda: _dispatch(
                stop_runner, "stop", _unit(evidence["run_id"]),
                stop_deadline - clock(),
            ).returncode,
            stop_deadline,
        )
    except Exception:
        return "uncertain"
    if type(result) is not int or result != 0:
        return "uncertain"
    # Stop the already-admitted exact instance before potentially slow evidence I/O.
    # Drift still makes the outcome uncertain; it must not prevent the safety stop.
    try:
        _bounded(lambda: _safe_revalidate(permission), stop_deadline)
    except (SupervisionError, bounded_io.BoundedIOError):
        return "uncertain"
    while clock() < stop_deadline:
        try:
            observation = _bounded(
                lambda: _read_observation(evidence, stop_runner, clock, stop_deadline),
                stop_deadline,
            )
        except (SupervisionError, bounded_io.BoundedIOError):
            return "uncertain"
        if clock() >= stop_deadline:
            return "uncertain"
        if observation["decision"] != "running" and observation["released"]:
            return "uncertain" if (start_uncertain or preserve_uncertain) else "incomplete"
        remaining = stop_deadline - clock()
        if remaining <= 0:
            break
        sleeper(min(POLL_SECONDS, remaining))
    return "uncertain"


def _outcome(evidence, intent_digest, state):
    return {
        "schema_version": RECEIPT_VERSION,
        "state": state,
        "backup": str(evidence["backup_path"]),
        "backup_identity": list(evidence["backup_identity"]),
        "creation_evidence_sha256": hashlib.sha256(json.dumps(
            evidence["artifact_digests"], sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "run_id": evidence["run_id"],
        "profile_id": evidence["profile_id"],
        "notification_mode": "none",
        "intent_sha256": intent_digest,
        "result": {"state": state},
    }


def supervise(path: Path, *, runner=None, monotonic=None, sleep=None):
    """Admit, start exactly one instance, and stop only that instance if needed."""
    clock = monotonic or time.monotonic
    sleeper = sleep or time.sleep
    with admit(path) as permission:
        evidence = permission.evidence
        run_id = evidence["run_id"]
        unit = _unit(run_id)
        gate_deadline = clock() + OBSERVATION_SECONDS
        result_deadline = gate_deadline
        gate_runner = _DeadlineRunner(runner, clock, gate_deadline)
        try:
            _bounded(lambda: (permission.revalidate(), None)[1], gate_deadline)
            _bounded(lambda: preflight.run_gate(run_id, runner=gate_runner), gate_deadline)
            _bounded(lambda: (permission.revalidate(), None)[1], gate_deadline)
            _bounded(lambda: _require_runtime_cap(unit, gate_runner), gate_deadline)
            _bounded(lambda: _require_api_fence(gate_runner, gate_deadline), gate_deadline)
        except SupervisionError:
            raise
        except bounded_io.BoundedIOError:
            raise SupervisionError("supervision_gate_uncertain") from None
        # The worker holds the exclusive fence before it connects.  No pipeline
        # effect is permitted until the protected evidence is rechecked and the
        # authenticated exact-unit peer receives the single authorization.
        worker_uid, worker_gid = _worker_identity()
        dispatched = False
        start_uncertain = True
        try:
            with fence_runtime.canary_channel(
                run_id, worker_uid=worker_uid, worker_gid=worker_gid
            ) as channel:
                dispatched = True
                start_result = _bounded(
                    lambda: _dispatch(
                        gate_runner, "start", unit, gate_deadline - clock(),
                    ).returncode,
                    gate_deadline,
                )
                if type(start_result) is int and start_result == 0:
                    channel.wait_ready(gate_deadline)
                    _bounded(lambda: (permission.revalidate(), None)[1], gate_deadline)
                    _bounded(lambda: _require_runtime_cap(unit, gate_runner), gate_deadline)
                    _bounded(
                        lambda: _require_api_fence(gate_runner, gate_deadline), gate_deadline
                    )
                    channel.allow(gate_deadline)
                    start_uncertain = False
        except Exception:
            if not dispatched:
                raise SupervisionError("supervision_gate_uncertain") from None
        if start_uncertain:
            result_deadline = clock() + STOP_SECONDS
            state = _stop_exact(
                permission, evidence, runner, clock, sleeper, True,
                stop_deadline=result_deadline,
            )
        else:
            state, _observation = _observe_until(
                evidence, gate_runner, clock, sleeper, gate_deadline
            )
            if state in {"timeout", "uncertain"}:
                result_deadline = clock() + STOP_SECONDS
                state = _stop_exact(
                    permission, evidence, runner, clock, sleeper, False,
                    state == "uncertain", stop_deadline=result_deadline,
                )
        record = _outcome(evidence, permission.intent_digest, state)
        try:
            _bounded(lambda: permission._write_outcome(record), result_deadline)
        except (SupervisionError, bounded_io.BoundedIOError):
            raise SupervisionError("supervision_outcome_uncertain") from None
        return record


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise SupervisionError("arguments_invalid")


def main(argv=None, *, runner=None, monotonic=None, sleep=None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if sum(token == "--backup" or token.startswith("--backup=") for token in tokens) != 1:
        print("CANARY_SUPERVISION: FAIL (arguments_invalid)", file=sys.stderr)
        return 1
    parser = _Parser(
        description="Bounded, exact-instance offline canary supervision.",
        allow_abbrev=False,
    )
    parser.add_argument("--backup", required=True)
    try:
        args = parser.parse_args(argv)
        path = Path(args.backup)
        if not path.is_absolute() or str(path) != args.backup:
            raise SupervisionError("arguments_invalid")
        result = supervise(
            path, runner=runner, monotonic=monotonic, sleep=sleep,
        )
    except SystemExit:
        raise
    except SupervisionError as exc:
        print(f"CANARY_SUPERVISION: FAIL ({exc.code})", file=sys.stderr)
        return 1
    except Exception:
        print("CANARY_SUPERVISION: FAIL (supervision_uncertain)", file=sys.stderr)
        return 1
    state = result.get("state") if isinstance(result, dict) else None
    if state == "completed":
        print("CANARY_SUPERVISION: PASS (completed)")
        return 0
    if state == "incomplete":
        print("CANARY_SUPERVISION: INCOMPLETE (bounded operation ended without completion)")
        return 2
    if state == "uncertain":
        print("CANARY_SUPERVISION: UNCERTAIN (ownership or evidence not proven)",
              file=sys.stderr)
        return 3
    print("CANARY_SUPERVISION: FAIL (supervision_result_invalid)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
