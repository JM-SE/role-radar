#!/usr/bin/env python3
"""Fixed, receipt-bound cleanup of the three Role Radar producer timers."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from scripts import bounded_canary_artifacts as artifacts
from scripts import bounded_canary_backup as backup
from scripts import bounded_canary_create as creation
from scripts import bounded_canary_preflight as preflight

INTENT_NAME = "timer-cleanup-intent.json"
OUTCOME_NAME = "timer-cleanup-outcome.json"
RECEIPT_VERSION = 1
TIMER_UNITS = (
    "role-radar-scheduler.timer",
    "role-radar-continuous-discovery.timer",
    "role-radar-continuous-acquisition.timer",
)
BASELINE_UNITS = tuple(sorted(preflight.RUNTIME_BASELINE))


class TimerError(Exception):
    def __init__(self, code: str, recovery: str | None = None):
        super().__init__(code)
        self.code = code
        self.recovery = recovery


def _snapshot(runner, *, require_runtime=True):
    baseline = preflight._show(BASELINE_UNITS, preflight.BASELINE_PROPERTIES, runner)
    if set(baseline) != set(BASELINE_UNITS):
        raise TimerError("runtime_baseline_invalid")
    for unit, record in baseline.items():
        if (record.get("Id") != unit or record.get("LoadState") != "loaded"
                or (require_runtime and not preflight._runtime_state(record, unit))):
            raise TimerError("runtime_baseline_invalid")
    timers = preflight._show(TIMER_UNITS, preflight.TIMER_PROPERTIES, runner)
    if set(timers) != set(TIMER_UNITS):
        raise TimerError("systemd_proof_unavailable")
    for unit, record in timers.items():
        if record.get("Id") != unit or record.get("LoadState") != "loaded":
            raise TimerError("systemd_proof_unavailable")
    return {"baseline": baseline, "timers": timers}


def _write_receipt(evidence, name: str, record: dict):
    data = (json.dumps(record, sort_keys=True) + "\n").encode()
    root_fds, root_ids = evidence["root_fds"], evidence["root_ids"]
    root_fd, child_fd = evidence["root_fd"], evidence["child_fd"]
    path = evidence["backup_path"]

    def validate():
        creation._validate_backup_anchors(
            root_fds, root_ids, root_fd, child_fd, evidence["backup_identity"], path.name
        )

    try:
        identity = artifacts.write_new_at(
            child_fd, name, data, uid=0, gid=0, mode=0o600, chown=backup._chown_new,
            require_owner=lambda info, uid, gid: backup._require_owner(
                info, uid, gid, "timer_evidence_invalid"), validate_parent=validate,
        )
        os.fsync(child_fd)
        os.fsync(root_fd)
        return identity
    except Exception:
        raise TimerError("timer_cleanup_uncertain", str(path)) from None


def _revalidate_before_dispatch(path, evidence, expected_intent, created_identity):
    try:
        creation._validate_backup_anchors(
            evidence["root_fds"], evidence["root_ids"], evidence["root_fd"],
            evidence["child_fd"], evidence["backup_identity"], path.name,
        )
        creation._validate_retained_backup(
            evidence["child_fd"], evidence["artifact_identities"],
            evidence["artifact_digests"],
        )
        with creation._open_creation_evidence(path) as current:
            unchanged = (
                current["backup_identity"] == evidence["backup_identity"]
                and current["root_ids"] == evidence["root_ids"]
                and current["run_id"] == evidence["run_id"]
                and current["profile_id"] == evidence["profile_id"]
                and current["artifact_identities"] == evidence["artifact_identities"]
                and current["artifact_digests"] == evidence["artifact_digests"]
            )
        if not unchanged:
            raise ValueError
        creation._validate_backup_anchors(
            evidence["root_fds"], evidence["root_ids"], evidence["root_fd"],
            evidence["child_fd"], evidence["backup_identity"], path.name,
        )
        creation._validate_retained_backup(
            evidence["child_fd"], evidence["artifact_identities"],
            evidence["artifact_digests"],
        )
        data, identity, digest = creation._read_at(evidence["child_fd"], INTENT_NAME)
        if (data != expected_intent or identity[:2] != created_identity
                or digest != hashlib.sha256(expected_intent).hexdigest()):
            raise ValueError
        creation._validate_backup_anchors(
            evidence["root_fds"], evidence["root_ids"], evidence["root_fd"],
            evidence["child_fd"], evidence["backup_identity"], path.name,
        )
    except Exception:
        raise TimerError("timer_cleanup_evidence_changed", str(path)) from None


def _execute_cleanup(path: Path, evidence, runner):
    names = set(os.listdir(evidence["child_fd"]))
    if INTENT_NAME in names or OUTCOME_NAME in names:
        raise TimerError("timer_cleanup_exists", str(path))
    before = _snapshot(runner)
    intent = {
        "schema_version": RECEIPT_VERSION, "state": "attempted",
        "backup": str(path), "backup_identity": list(evidence["backup_identity"]),
        "run_id": evidence["run_id"], "profile_id": evidence["profile_id"],
        "timer_units": list(TIMER_UNITS), "before": before,
    }
    intent_data = (json.dumps(intent, sort_keys=True) + "\n").encode()
    intent_identity = _write_receipt(evidence, INTENT_NAME, intent)
    intent_hash = hashlib.sha256(intent_data).hexdigest()
    _revalidate_before_dispatch(path, evidence, intent_data, intent_identity)
    dispatch_error = False
    returncode = None
    try:
        result = (runner or subprocess.run)(
            ["/usr/bin/systemctl", "disable", "--now", *TIMER_UNITS],
            capture_output=True, text=True, timeout=15, check=False, shell=False,
            env=dict(preflight.CLEAN_ENV),
        )
        returncode = result.returncode
    except Exception:
        dispatch_error = True
    after = None
    with contextlib.suppress(Exception):
        after = _snapshot(runner, require_runtime=False)
    evidence_changed = False
    try:
        _revalidate_before_dispatch(path, evidence, intent_data, intent_identity)
    except TimerError:
        evidence_changed = True
    if dispatch_error or after is None or evidence_changed:
        state = "uncertain"
    elif returncode != 0 or after["baseline"] != before["baseline"] \
            or any(not preflight._quiescent_timer(after["timers"][unit], unit)
                   for unit in TIMER_UNITS):
        state = "incomplete"
    else:
        state = "completed"
    outcome = {
        "schema_version": RECEIPT_VERSION, "state": state,
        "backup": str(path), "backup_identity": list(evidence["backup_identity"]),
        "run_id": evidence["run_id"], "intent_sha256": intent_hash,
        "returncode": returncode, "before": before, "after": after,
    }
    _write_receipt(evidence, OUTCOME_NAME, outcome)
    if state != "completed":
        raise TimerError(f"timer_cleanup_{state}", str(path))


def cleanup(path: Path, runner=None):
    if os.geteuid() != 0:
        raise TimerError("operator_privilege_required", str(path))
    if not path.is_absolute():
        raise TimerError("arguments_invalid")
    failure = None
    try:
        with creation._open_creation_evidence(path) as evidence:
            try:
                if path != evidence["backup_path"]:
                    raise TimerError("creation_evidence_invalid", str(path))
                _execute_cleanup(path, evidence, runner)
            except TimerError as exc:
                # The evidence context maps exceptions from its consumer to an evidence error.
                failure = exc
            except Exception:
                failure = TimerError("timer_cleanup_uncertain", str(path))
    except creation.CreationError:
        if failure is None:
            failure = TimerError("creation_evidence_invalid", str(path))
    if failure is not None:
        raise failure


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise TimerError("arguments_invalid")


def main(argv=None, *, runner=None) -> int:
    tokens = sys.argv[1:] if argv is None else argv
    if sum(token == "--backup" or token.startswith("--backup=") for token in tokens) > 1:
        print("CANARY_TIMER_CLEANUP: FAIL (arguments_invalid)", file=sys.stderr)
        return 1
    parser = _Parser(
        description="Stop and disable only the three fixed Role Radar producer timers.",
        allow_abbrev=False,
    )
    parser.add_argument("--backup", required=True, help="protected successful-creation evidence")
    try:
        args = parser.parse_args(argv)
        path = Path(args.backup)
        if not path.is_absolute() or str(path) != args.backup:
            raise TimerError("arguments_invalid")
        cleanup(path, runner=runner)
    except SystemExit:
        raise
    except TimerError as exc:
        suffix = f"; recovery={exc.recovery}" if exc.recovery else ""
        print(f"CANARY_TIMER_CLEANUP: FAIL ({exc.code}{suffix})", file=sys.stderr)
        return 1
    except Exception:
        print("CANARY_TIMER_CLEANUP: FAIL (timer_cleanup_uncertain)", file=sys.stderr)
        return 1
    print("CANARY_TIMER_CLEANUP: PASS (timers stopped and disabled)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
