import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/bounded_canary_preflight.py"
RUN_ID = "00000000-0000-4000-8000-000000000001"
CANARY_PREFIX = "role-radar-canary-worker@"
SERVICES = (
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
TIMERS = (
    "role-radar-scheduler.timer",
    "role-radar-continuous-discovery.timer",
    "role-radar-continuous-acquisition.timer",
)
CREDENTIALS = (
    "query-hmac:/etc/role-radar/credentials/query-hmac "
    "brave-free:/etc/role-radar/credentials/brave-free "
    "tavily-free:/etc/role-radar/credentials/tavily-free"
)
UNIT_FRAGMENT = "/etc/systemd/system/role-radar-canary-worker@.service"


def _execstart(argv, path="/usr/bin/env", metadata="ignore_errors=no"):
    rendered = " ".join(argv)
    return f"{{ path={path} ; argv[]=/usr/bin/env {rendered} ; {metadata} ; }}"


def _block(unit, *, active="inactive", sub="dead", pid="0", props=None):
    unit_match = re.search(r"@([0-9a-f-]{36})\.service$", unit)
    instance_id = unit_match.group(1) if unit_match else RUN_ID
    values = {
        "Id": unit,
        "LoadState": "loaded",
        "ActiveState": active,
        "SubState": sub,
        "MainPID": pid,
        "Type": "oneshot",
        "User": "role-radar",
        "WorkingDirectory": "/opt/role-radar",
        "Restart": "no",
        "ExecStart": _execstart(["role-radar", "worker", "--run-id", instance_id]),
        "ExecStartPre": "",
        "EnvironmentFiles": "/etc/role-radar/role-radar.env (ignore_errors=no)",
        "Environment": "PATH=/opt/role-radar/.venv/bin:/usr/bin",
        "LoadCredential": CREDENTIALS,
        "FragmentPath": (
            UNIT_FRAGMENT if unit.startswith(CANARY_PREFIX) else f"/etc/systemd/system/{unit}"
        ),
        "DropInPaths": "",
        "NeedDaemonReload": "no",
        "UnitFileState": "enabled",
    }
    values.update(props or {})
    return "\n".join(f"{key}={value}" for key, value in values.items()) + "\n\n"


def _records(run_id=RUN_ID):
    values = {}
    for unit in SERVICES:
        if unit in {"role-radar-api.service", "llm-broker-api.service",
                    "llm-broker-worker.service", "llama-server.service", "llama-swap.service"}:
            values[unit] = _block(unit, active="active", sub="running", pid="100")
        elif unit == "role-radar-worker.service":
            values[unit] = _block(unit, props={"UnitFileState": "disabled"})
        elif unit in {
            "role-radar-scheduler.service",
            "role-radar-continuous-discovery.service",
            "role-radar-continuous-acquisition.service",
        }:
            values[unit] = _block(unit, props={"UnitFileState": "static"})
        else:
            values[unit] = _block(unit)
    for unit in TIMERS:
        values[unit] = (
            "\n".join(
                (
                    f"Id={unit}",
                    "LoadState=loaded",
                    "ActiveState=inactive",
                    "SubState=dead",
                    "UnitFileState=disabled",
                )
            )
            + "\n\n"
        )
    exact = f"{CANARY_PREFIX}{run_id}.service"
    values[exact] = _block(
        exact, props={"ExecStart": _execstart(["role-radar", "worker", "--run-id", run_id])}
    )
    return values


def test_systemd_omitted_and_redacted_properties_are_verified_from_unit_config(monkeypatch, capsys):
    from scripts import bounded_canary_preflight as adapter

    records = _records()
    calls = []
    config = "\n".join(
        (
            "# /etc/systemd/system/role-radar-canary-worker@.service",
            "[Unit]",
            "Description=role-radar bounded canary worker for run %i",
            "After=network-online.target",
            "[Service]",
            "Type=oneshot",
            "User=role-radar",
            "WorkingDirectory=/opt/role-radar",
            "EnvironmentFile=/etc/role-radar/role-radar.env",
            "LoadCredential=query-hmac:/etc/role-radar/credentials/query-hmac",
            "LoadCredential=brave-free:/etc/role-radar/credentials/brave-free",
            "LoadCredential=tavily-free:/etc/role-radar/credentials/tavily-free",
            "Environment=PATH=/opt/role-radar/.venv/bin:/usr/bin",
            "ExecStart=/usr/bin/env role-radar worker --run-id %i",
            "Restart=no",
            "",
        )
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1:3] == ["list-units", "--all"]:
            return subprocess.CompletedProcess(command, 0, "", "private list stderr")
        if command[1] == "cat":
            return subprocess.CompletedProcess(command, 0, config, "private cat stderr")
        if command[1] == "show":
            property_arg = next(item for item in command if item.startswith("--property="))
            properties = property_arg.split("=", 1)[1].split(",")
            names = command[command.index(property_arg) + 1 :]
            chunks = []
            for name in names:
                if name not in records:
                    continue
                parsed = dict(line.split("=", 1) for line in records[name].splitlines() if line)
                if name.startswith(CANARY_PREFIX):
                    parsed.pop("ExecStartPre", None)
                    parsed["LoadCredential"] = "[unprintable]"
                    parsed["FragmentPath"] = UNIT_FRAGMENT
                    parsed["DropInPaths"] = ""
                    parsed["NeedDaemonReload"] = "no"
                chunks.extend(f"{key}={parsed[key]}\n" for key in properties if key in parsed)
                chunks.append("\n")
            return subprocess.CompletedProcess(command, 0, "".join(chunks), "private show stderr")
        return subprocess.CompletedProcess(command, 1, "", "private error")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    code = adapter.main(["--run-id", RUN_ID])
    output = capsys.readouterr()
    assert code == 0, output.err
    assert output.out == "SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)\n"
    assert output.err == ""
    assert any(command[1] == "cat" for command, _ in calls)
    assert all(call[1]["shell"] is False for call in calls)
    assert all(command[0] == "/usr/bin/systemctl" for command, _ in calls)
    assert "private" not in output.err


def _unit_config(record):
    values = dict(line.split("=", 1) for line in record.splitlines() if line)
    environment_file = values["EnvironmentFiles"].removesuffix(" (ignore_errors=no)")
    lines = [
        f"# {UNIT_FRAGMENT}",
        "[Service]",
        f"Type={values['Type']}",
        f"User={values['User']}",
        f"WorkingDirectory={values['WorkingDirectory']}",
        f"EnvironmentFile={environment_file}",
    ]
    lines.extend(f"LoadCredential={item}" for item in values["LoadCredential"].split())
    lines.extend(
        (
            f"Environment={values['Environment']}",
            "ExecStart=/usr/bin/env role-radar worker --run-id %i",
        )
    )
    if values.get("ExecStartPre"):
        lines.append(f"ExecStartPre={values['ExecStartPre']}")
    lines.append(f"Restart={values['Restart']}")
    return "\n".join(lines) + "\n"


def _invoke(
    monkeypatch,
    capsys,
    records,
    args=None,
    listed=(),
    *,
    cat_output=None,
    cat_returncode=0,
    show_overrides=None,
):
    from scripts import bounded_canary_preflight as adapter

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1:3] == ["list-units", "--all"]:
            out = "".join(f"{unit} loaded inactive dead RoleRadar canary\n" for unit in listed)
            return subprocess.CompletedProcess(command, 0, out, "private list stderr")
        if command[1] == "cat":
            unit = command[-1]
            output = cat_output if cat_output is not None else _unit_config(records[unit])
            return subprocess.CompletedProcess(command, cat_returncode, output, "private cat error")
        if command[1] == "show":
            property_arg = next(item for item in command if item.startswith("--property="))
            properties = property_arg.split("=", 1)[1].split(",")
            names = command[command.index(property_arg) + 1 :]
            chunks = []
            for name in names:
                if name not in records:
                    continue
                parsed = dict(line.split("=", 1) for line in records[name].splitlines() if line)
                if name.startswith(CANARY_PREFIX):
                    parsed.pop("ExecStartPre", None)
                    parsed["LoadCredential"] = "[unprintable]"
                    parsed.setdefault("FragmentPath", UNIT_FRAGMENT)
                    parsed.setdefault("DropInPaths", "")
                    parsed.setdefault("NeedDaemonReload", "no")
                    parsed.update(show_overrides or {})
                chunks.extend(f"{key}={parsed[key]}\n" for key in properties if key in parsed)
                chunks.append("\n")
            return subprocess.CompletedProcess(command, 0, "".join(chunks), "private show stderr")
        return subprocess.CompletedProcess(command, 1, "", "private stderr")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    code = adapter.main(args or ["--run-id", RUN_ID])
    return code, capsys.readouterr(), calls


def _expect_pass(monkeypatch, capsys, records=None, *, listed=()):
    code, output, calls = _invoke(monkeypatch, capsys, records or _records(), listed=listed)
    assert code == 0, output.err
    assert output.out == "SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)\n"
    assert output.err == ""
    assert calls and all(call[1]["timeout"] <= 15 for call in calls)
    assert all(call[1]["shell"] is False for call in calls)
    assert all(command[0] == "/usr/bin/systemctl" for command, _ in calls)
    assert all(command[1] in {"show", "list-units", "cat"} for command, _ in calls)
    assert all(
        call[1]["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"} for call in calls
    )
    assert all("private" not in str(call) for call in calls)


@pytest.mark.parametrize(
    ("show_overrides", "cat_source"),
    [
        ({"FragmentPath": "/run/systemd/generator/role-radar-canary-worker@.service"}, None),
        (
            {
                "DropInPaths": (
                    "/etc/systemd/system/role-radar-canary-worker@.service.d/override.conf"
                )
            },
            None,
        ),
        ({"NeedDaemonReload": "yes"}, None),
        ({}, "/etc/systemd/system/role-radar-canary-worker@.service.d/override.conf"),
    ],
)
def test_worker_unit_origin_dropins_and_reload_state_fail_closed(
    monkeypatch, capsys, show_overrides, cat_source
):
    records = _records()
    unit = f"{CANARY_PREFIX}{RUN_ID}.service"
    cat_output = _unit_config(records[unit])
    if cat_source:
        cat_output = cat_output.replace(UNIT_FRAGMENT, cat_source)
    code, output, calls = _invoke(
        monkeypatch,
        capsys,
        records,
        cat_output=cat_output,
        show_overrides=show_overrides,
    )
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (canary_worker_contract_invalid)\n"
    assert calls


@pytest.mark.parametrize(
    "directive",
    [
        "LoadCredentialEncrypted=extra:/run/extra",
        "ImportCredential=external-*",
        "SetCredential=extra:value",
        "SetCredentialEncrypted=extra:value",
    ],
)
def test_additional_credential_sources_are_rejected(monkeypatch, capsys, directive):
    records = _records()
    unit = f"{CANARY_PREFIX}{RUN_ID}.service"
    cat_output = _unit_config(records[unit]).replace("Restart=no\n", f"{directive}\nRestart=no\n")
    code, output, calls = _invoke(monkeypatch, capsys, records, cat_output=cat_output)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (canary_worker_contract_invalid)\n"
    assert calls


@pytest.mark.parametrize("spacing", [" ", "\t"])
@pytest.mark.parametrize(
    "assignment",
    [
        "ExecStartPre=/bin/true",
        "LoadCredentialEncrypted=extra:/run/extra",
        "ImportCredential=external-*",
        "SetCredential=extra:value",
        "SetCredentialEncrypted=extra:value",
    ],
)
def test_worker_forbidden_directives_with_assignment_whitespace_fail_closed(
    monkeypatch, capsys, spacing, assignment
):
    records = _records()
    unit = f"{CANARY_PREFIX}{RUN_ID}.service"
    key, value = assignment.split("=", 1)
    cat_output = _unit_config(records[unit]) + f"{key}{spacing}={value}\n"
    code, output, calls = _invoke(monkeypatch, capsys, records, cat_output=cat_output)
    assert code == 1
    assert output.out == ""
    assert output.err == ("SYSTEMD_ISOLATION_GATE: FAIL (canary_worker_contract_invalid)\n")
    assert all(command[1] in {"show", "list-units", "cat"} for command, _kwargs in calls)


def test_systemctl_cat_failure_is_privacy_safe(monkeypatch, capsys):
    code, output, calls = _invoke(monkeypatch, capsys, _records(), cat_returncode=1)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n"
    assert calls


def test_active_api_and_four_established_runtime_baselines_are_accepted(monkeypatch, capsys):
    _expect_pass(monkeypatch, capsys)


@pytest.mark.parametrize(
    "metadata",
    [
        "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0",
        "ignore_errors=no ; start_time=[Tue 2026-10-06 00:00:00 UTC] ; "
        "stop_time=[Tue 2026-10-06 00:00:01 UTC] ; pid=123 ; code=exited ; status=1/FAILURE",
    ],
)
def test_resolved_worker_execstart_accepts_systemd_result_metadata(monkeypatch, capsys, metadata):
    records = _records()
    unit = f"{CANARY_PREFIX}{RUN_ID}.service"
    values = dict(line.split("=", 1) for line in records[unit].splitlines() if line)
    values["ExecStart"] = _execstart(
        ["role-radar", "worker", "--run-id", RUN_ID], metadata=metadata
    )
    records[unit] = "".join(f"{key}={value}\n" for key, value in values.items()) + "\n"
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 0
    assert output.out == "SYSTEMD_ISOLATION_GATE: PASS (gate only; not overall readiness)\n"
    assert output.err == ""
    assert calls and all(command[1] in {"show", "list-units", "cat"} for command, _ in calls)


@pytest.mark.parametrize("unit", [
    "role-radar-worker.service",
    "role-radar-scheduler.service",
    "role-radar-continuous-discovery.service",
    "role-radar-continuous-acquisition.service",
])
def test_running_worker_or_producer_is_rejected(monkeypatch, capsys, unit):
    records = _records()
    values = dict(line.split("=", 1) for line in records[unit].splitlines() if line)
    values.update(ActiveState="active", SubState="running", MainPID="123")
    records[unit] = "".join(f"{key}={value}\n" for key, value in values.items()) + "\n"
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (producer_or_canary_active)\n"
    assert calls


@pytest.mark.parametrize("changes", [
    {"User": "root"},
    {"User": "other-user"},
    {"WorkingDirectory": "/tmp"},
    {"Environment": "PATH=/tmp:/usr/bin"},
    {"EnvironmentFiles": "/tmp/injected.env (ignore_errors=no)"},
    {"ExecStartPre": "/bin/echo ready"},
    {"ExecStart": _execstart(["echo", "role-radar", "worker", "--run-id", RUN_ID])},
    {"ExecStart": _execstart(["role-radar", "worker", "--run-id", RUN_ID, "--extra"])},
    {"ExecStart": _execstart(["role-radar", "worker", "--run-id", "%i"])},
    {"ExecStart": _execstart(["role-radar", "worker", "--run-id", "%%i"])},
    {"ExecStart": _execstart(["role-radar", "worker", "--run-id", RUN_ID], path="/bin/echo")},
])
def test_exact_worker_contract_rejects_mutated_command_and_context(monkeypatch, capsys, changes):
    records = _records()
    unit = f"{CANARY_PREFIX}{RUN_ID}.service"
    old = records[unit]
    values = dict(line.split("=", 1) for line in old.splitlines() if line)
    values.update(changes)
    records[unit] = "".join(f"{key}={value}\n" for key, value in values.items()) + "\n"
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (canary_worker_contract_invalid)\n"
    assert calls


def test_run_id_validation_and_help_are_public_and_side_effect_free(monkeypatch, capsys):
    code, output, calls = _invoke(monkeypatch, capsys, {}, ["--run-id", "$(touch nope)"])
    assert code == 2
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (run_id_invalid)\n"
    assert calls == []
    from scripts import bounded_canary_preflight as adapter

    try:
        adapter.main(["--help"])
    except SystemExit as help_exit:
        assert help_exit.code == 0
    help_output = capsys.readouterr()
    assert "gate only" in help_output.out.lower()
    assert "--run-id" in help_output.out


@pytest.mark.parametrize("field,value", [
    ("ActiveState", "active"), ("MainPID", "9"), ("LoadState", "not-found"),
])
def test_every_unrelated_instantiated_canary_is_quiescent(monkeypatch, capsys, field, value):
    records = _records()
    unrelated = f"{CANARY_PREFIX}00000000-0000-4000-8000-000000000002.service"
    active, sub, pid = "inactive", "dead", "0"
    if field == "ActiveState":
        active, sub = value, "running"
    elif field == "MainPID":
        pid = value
    else:
        active, sub = "inactive", "dead"
    records[unrelated] = _block(unrelated, active=active, sub=sub, pid=pid,
                                props={"LoadState": value} if field == "LoadState" else None)
    code, output, calls = _invoke(monkeypatch, capsys, records, listed=[unrelated])
    assert code == 1
    assert output.out == ""
    assert output.err in {
        "SYSTEMD_ISOLATION_GATE: FAIL (producer_or_canary_active)\n",
        "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n",
    }
    assert calls


@pytest.mark.parametrize("unit,field,value,code_expected", [
    ("role-radar-worker.service", "MainPID", "", "producer_or_canary_active"),
    ("role-radar-worker.service", "MainPID", "-1", "producer_or_canary_active"),
    ("role-radar-worker.service", "MainPID", "01", "producer_or_canary_active"),
    ("role-radar-worker.service", "Id", "wrong.service", "systemd_proof_unavailable"),
    ("role-radar-api.service", "Id", "wrong.service", "systemd_proof_unavailable"),
    ("llm-broker-api.service", "ActiveState", "inactive", "runtime_baseline_invalid"),
    ("llm-broker-worker.service", "LoadState", "not-found", "systemd_proof_unavailable"),
])
def test_service_identity_pid_and_baseline_fail_closed(
    monkeypatch, capsys, unit, field, value, code_expected
):
    records = _records()
    values = dict(line.split("=", 1) for line in records[unit].splitlines() if line)
    values[field] = value
    records[unit] = "".join(f"{key}={value}\n" for key, value in values.items()) + "\n"
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert output.err == f"SYSTEMD_ISOLATION_GATE: FAIL ({code_expected})\n"
    assert calls


def test_missing_baseline_unit_and_unavailable_proof_fail_closed(monkeypatch, capsys):
    records = _records()
    del records["llm-broker-api.service"]
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert calls


def test_missing_exact_instance_record_fails_closed(monkeypatch, capsys):
    records = _records()
    del records[f"{CANARY_PREFIX}{RUN_ID}.service"]
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n"
    assert calls


@pytest.mark.parametrize("target", ["timer", "exact_instance"])
def test_timer_and_exact_instance_identity_must_match_requested_unit(
    monkeypatch, capsys, target
):
    records = _records()
    unit = TIMERS[0] if target == "timer" else f"{CANARY_PREFIX}{RUN_ID}.service"
    values = dict(line.split("=", 1) for line in records[unit].splitlines() if line)
    values["Id"] = "role-radar-canary-worker@00000000-0000-4000-8000-000000000002.service"
    records[unit] = "".join(f"{key}={value}\n" for key, value in values.items()) + "\n"
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n"
    assert calls


def test_duplicate_canary_listing_fails_privacy_safely(monkeypatch, capsys):
    unrelated = f"{CANARY_PREFIX}00000000-0000-4000-8000-000000000002.service"
    records = _records() | {unrelated: _block(unrelated)}
    code, output, calls = _invoke(
        monkeypatch, capsys, records, listed=(unrelated, unrelated)
    )
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n"
    assert calls


def test_timers_need_no_pid_and_exact_worker_credentials_remain_required(monkeypatch, capsys):
    _expect_pass(monkeypatch, capsys)
    unrelated = f"{CANARY_PREFIX}00000000-0000-4000-8000-000000000002.service"
    _expect_pass(
        monkeypatch,
        capsys,
        _records() | {unrelated: _block(unrelated)},
        listed=(unrelated,),
    )
    records = _records()
    unit = f"{CANARY_PREFIX}{RUN_ID}.service"
    records[unit] = records[unit].replace(CREDENTIALS, "one-secret-looking-value")
    code, output, calls = _invoke(monkeypatch, capsys, records)
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (canary_worker_contract_invalid)\n"
    assert calls


@pytest.mark.parametrize("returncode,stdout", [
    (1, "private systemctl error"),
    (0, "Id=role-radar-api.service\nId=duplicate.service\n"),
    (0, "Id=role-radar-api.service\nUnexpected=private\n"),
    (0, "Id=role-radar-api.service\n"),
])
def test_nonzero_duplicate_unknown_and_missing_show_proof_fail_safely(
    monkeypatch, capsys, returncode, stdout
):
    from scripts import bounded_canary_preflight as adapter

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, returncode, stdout, "private stderr")

    monkeypatch.setattr(adapter.subprocess, "run", fake_run)
    code = adapter.main(["--run-id", RUN_ID])
    output = capsys.readouterr()
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n"
    assert calls
    assert "private" not in output.err
    assert all(command[0] == "/usr/bin/systemctl" and kwargs["shell"] is False
               for command, kwargs in calls)


def test_list_and_show_proof_are_strict_and_timeout_is_sanitized(monkeypatch, capsys):
    from scripts import bounded_canary_preflight as adapter

    calls = []

    def timeout(command, **kwargs):
        calls.append((command, kwargs))
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], "private output")

    monkeypatch.setattr(adapter.subprocess, "run", timeout)
    code = adapter.main(["--run-id", RUN_ID])
    output = capsys.readouterr()
    assert code == 1
    assert output.out == ""
    assert output.err == "SYSTEMD_ISOLATION_GATE: FAIL (systemd_proof_unavailable)\n"
    assert calls
