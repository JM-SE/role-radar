#!/usr/bin/env python3
"""Read-only systemd isolation gate; this does not establish overall readiness."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

SERVICE_UNITS = (
    "role-radar-api.service",
    "role-radar-worker.service",
    "role-radar-scheduler.service",
    "role-radar-continuous-discovery.service",
    "role-radar-continuous-acquisition.service",
    "llm-broker-api.service",
    "llm-broker-worker.service",
    "llama-server.service",
    "llama-swap.service",
)
TIMER_UNITS = (
    "role-radar-scheduler.timer",
    "role-radar-continuous-discovery.timer",
    "role-radar-continuous-acquisition.timer",
)
SERVICE_PROPERTIES = (
    "Id,LoadState,ActiveState,SubState,MainPID,UnitFileState,Type,User,WorkingDirectory,"
    "Restart,ExecStart,ExecStartPre,EnvironmentFiles,Environment,LoadCredential"
)
BASELINE_PROPERTIES = "Id,LoadState,ActiveState,SubState,MainPID,UnitFileState"
TIMER_PROPERTIES = "Id,LoadState,ActiveState,SubState,UnitFileState"
CANARY_PROPERTIES = SERVICE_PROPERTIES
RUN_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
CANARY_NAME = re.compile(r"role-radar-canary-worker@([0-9a-f-]{36})\.service\Z")
CANARY_PREFIX = "role-radar-canary-worker@"
RUNTIME_BASELINE = {
    "role-radar-api.service",
    "llm-broker-api.service",
    "llm-broker-worker.service",
    "llama-server.service",
    "llama-swap.service",
}
QUIESCENT_WORKERS = {"role-radar-worker.service"}
QUIESCENT_PRODUCERS = {
    "role-radar-scheduler.service",
    "role-radar-continuous-discovery.service",
    "role-radar-continuous-acquisition.service",
}
EXPECTED_CREDENTIALS = {
    "query-hmac:/etc/role-radar/credentials/query-hmac",
    "brave-free:/etc/role-radar/credentials/brave-free",
    "tavily-free:/etc/role-radar/credentials/tavily-free",
}
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}


class GateError(Exception):
    """A public, privacy-safe gate failure code."""


def _parse_blocks(output: str, expected_properties: set[str]) -> dict[str, dict[str, str]]:
    blocks: dict[str, dict[str, str]] = {}
    row: dict[str, str] = {}
    rows = []
    for line in [*output.splitlines(), ""]:
        if not line:
            if row:
                rows.append(row)
                row = {}
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in row or key not in expected_properties:
            raise GateError("systemd_proof_unavailable")
        row[key] = value
    for values in rows:
        unit = values.get("Id")
        if not unit or unit in blocks or set(values) != expected_properties:
            raise GateError("systemd_proof_unavailable")
        blocks[unit] = values
    return blocks


def _run(command: list[str], timeout: int, runner=None) -> subprocess.CompletedProcess:
    runner = runner or subprocess.run
    try:
        result = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=dict(CLEAN_ENV),
        )
    except Exception:
        raise GateError("systemd_proof_unavailable") from None
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise GateError("systemd_proof_unavailable")
    return result


def _show(units: tuple[str, ...] | list[str], properties: str, runner=None):
    if not units or any(not re.fullmatch(r"[a-zA-Z0-9_.@:-]+", unit) for unit in units):
        raise GateError("systemd_proof_unavailable")
    result = _run(
        ["/usr/bin/systemctl", "show", "--no-pager", f"--property={properties}", *units],
        15,
        runner,
    )
    return _parse_blocks(result.stdout, set(properties.split(",")))


def _canonical_pid(value: str) -> bool:
    return value == "0" or bool(re.fullmatch(r"[1-9][0-9]*", value))


def _runtime_state(record: dict[str, str], unit: str) -> bool:
    try:
        pid = record["MainPID"]
        if not _canonical_pid(pid):
            return False
        if unit in RUNTIME_BASELINE:
            return (
                record["ActiveState"] == "active"
                and record["SubState"] == "running"
                and record["UnitFileState"] == "enabled"
                and int(pid) > 0
            )
        if unit in QUIESCENT_WORKERS:
            return (
                record["ActiveState"] in {"inactive", "failed"}
                and record["SubState"] in {"dead", "failed"}
                and record["UnitFileState"] == "disabled"
                and pid == "0"
            )
        if unit in QUIESCENT_PRODUCERS:
            return (
                record["ActiveState"] in {"inactive", "failed"}
                and record["SubState"] in {"dead", "failed"}
                and record["UnitFileState"] == "static"
                and pid == "0"
            )
    except (KeyError, ValueError):
        return False
    return False


def _quiescent_timer(record: dict[str, str], unit: str) -> bool:
    return (
        record.get("Id") == unit
        and record.get("LoadState") == "loaded"
        and record.get("ActiveState") == "inactive"
        and record.get("SubState") == "dead"
        and record.get("UnitFileState") == "disabled"
    )


def _parse_exec_start(value: str) -> tuple[str, tuple[str, ...]] | None:
    if not value.startswith("{ ") or not value.endswith(" }"):
        return None
    fields = [field.strip() for field in value[1:-1].strip().split(";")]
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) < 3 or not fields[0].startswith("path=") or not fields[1].startswith("argv[]="):
        return None
    metadata = {}
    for field in fields[2:]:
        key, separator, item = field.partition("=")
        allowed_metadata = {"ignore_errors", "start_time", "stop_time", "pid", "code", "status"}
        if not separator or key not in allowed_metadata:
            return None
        if key in metadata:
            return None
        metadata[key] = item
    if metadata.get("ignore_errors") != "no":
        return None
    metadata_keys = set(metadata) - {"ignore_errors"}
    if metadata_keys not in (set(), {"start_time", "stop_time", "pid", "code", "status"}):
        return None
    if metadata_keys:
        for key in ("start_time", "stop_time"):
            timestamp = metadata[key]
            if not (
                timestamp == "[n/a]"
                or (
                    len(timestamp) > 2
                    and timestamp.startswith("[")
                    and timestamp.endswith("]")
                    and not any(char in timestamp[1:-1] for char in "]\r\n")
                )
            ):
                return None
        if not _canonical_pid(metadata["pid"]):
            return None
        if metadata["code"] not in {"exited", "killed", "dumped", "(null)"}:
            return None
        if metadata["status"] not in {"0/0", "1/FAILURE", "(null)"}:
            return None
    return fields[0][5:], tuple(fields[1][7:].split(" "))


def _worker_contract(record: dict[str, str], run_id: str) -> bool:
    try:
        parsed = _parse_exec_start(record["ExecStart"])
        credential_items = record["LoadCredential"].split()
        credentials = set(credential_items)
        return (
            record["Type"] == "oneshot"
            and record["Restart"] == "no"
            and record["User"] == "role-radar"
            and record["WorkingDirectory"] == "/opt/role-radar"
            and record["ExecStartPre"] == ""
            and record["EnvironmentFiles"] == "/etc/role-radar/role-radar.env (ignore_errors=no)"
            and record["Environment"].split() == ["PATH=/opt/role-radar/.venv/bin:/usr/bin"]
            and len(credential_items) == len(EXPECTED_CREDENTIALS)
            and credentials == EXPECTED_CREDENTIALS
            and parsed == (
                "/usr/bin/env",
                ("/usr/bin/env", "role-radar", "worker", "--run-id", run_id),
            )
        )
    except KeyError:
        return False


def _list_canaries(runner=None) -> tuple[str, ...]:
    result = _run(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--full",
            f"{CANARY_PREFIX}*.service",
        ],
        10,
        runner,
    )
    units = []
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=4)
        if len(fields) < 4:
            raise GateError("systemd_proof_unavailable")
        unit = fields[0]
        match = CANARY_NAME.fullmatch(unit)
        if not match or not RUN_ID.fullmatch(match.group(1)) or unit in units:
            raise GateError("systemd_proof_unavailable")
        if fields[1] not in {"loaded", "not-found", "error"}:
            raise GateError("systemd_proof_unavailable")
        units.append(unit)
    return tuple(units)


def _instance_records(run_id: str, listed: tuple[str, ...], runner=None):
    exact = f"{CANARY_PREFIX}{run_id}.service"
    units = tuple(dict.fromkeys((*listed, exact)))
    return _show(units, CANARY_PROPERTIES, runner)


def run_gate(run_id: str, runner=None) -> None:
    if not RUN_ID.fullmatch(run_id):
        raise GateError("run_id_invalid")
    service_records = _show(SERVICE_UNITS, BASELINE_PROPERTIES, runner)
    if set(service_records) != set(SERVICE_UNITS):
        raise GateError("systemd_proof_unavailable")
    for unit, record in service_records.items():
        if record.get("Id") != unit or record.get("LoadState") != "loaded":
            raise GateError("systemd_proof_unavailable")
        if not _runtime_state(record, unit):
            code = (
                "runtime_baseline_invalid"
                if unit in RUNTIME_BASELINE
                else "producer_or_canary_active"
            )
            raise GateError(code)

    timers = _show(TIMER_UNITS, TIMER_PROPERTIES, runner)
    if set(timers) != set(TIMER_UNITS):
        raise GateError("systemd_proof_unavailable")
    if any(not _quiescent_timer(record, unit) for unit, record in timers.items()):
        raise GateError("producer_or_canary_active")

    listed = _list_canaries(runner)
    instances = _instance_records(run_id, listed, runner)
    expected_instances = set(listed) | {f"{CANARY_PREFIX}{run_id}.service"}
    if set(instances) != expected_instances:
        raise GateError("systemd_proof_unavailable")
    for unit, record in instances.items():
        if record.get("Id") != unit or record.get("LoadState") != "loaded":
            raise GateError("systemd_proof_unavailable")
        pid = record.get("MainPID")
        if not _canonical_pid(pid):
            raise GateError("systemd_proof_unavailable")
        inactive = record.get("ActiveState") in {"inactive", "failed"}
        stopped = record.get("SubState") in {"dead", "failed"}
        if not inactive or not stopped or pid != "0":
            raise GateError("producer_or_canary_active")
        if not _worker_contract(record, unit.removeprefix(CANARY_PREFIX).removesuffix(".service")):
            raise GateError("canary_worker_contract_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only SYSTEMD isolation gate only; not overall readiness."
    )
    parser.add_argument("--run-id", required=True, help="UUID for the future exact worker instance")
    args = parser.parse_args(argv)
    try:
        run_gate(args.run_id)
    except GateError as exc:
        print(f"SYSTEMD_ISOLATION_GATE: FAIL ({exc})", file=sys.stderr)
        return 2 if str(exc) == "run_id_invalid" else 1
    print("SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
