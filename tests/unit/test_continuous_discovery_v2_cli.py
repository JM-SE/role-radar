"""Gate A dedicated CLI registration/delegation checks."""

from __future__ import annotations

from argparse import ArgumentParser, Namespace

from role_radar.cli.continuous_discovery_v2 import (
    register_continuous_discovery_v2_parser,
    run_continuous_discovery_v2,
)
from role_radar.continuous_acquisition.runtime_discovery_v2 import RuntimeResult


def test_parser_registers_all_four_dedicated_commands() -> None:
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_continuous_discovery_v2_parser(subparsers)
    assert (
        parser.parse_args(["continuous-discovery-v2", "plan"]).continuous_discovery_v2_command
        == "plan"
    )
    assert (
        parser.parse_args(
            [
                "continuous-discovery-v2",
                "run-report-only",
                "--packet",
                "/tmp/packet.json",
                "--approval-reference",
                "approved-live-run",
                "--history-root",
                "/tmp/history",
                "--verdict",
                "/tmp/verdict.json",
            ]
        ).continuous_discovery_v2_command
        == "run-report-only"
    )
    parsed = parser.parse_args(
        [
            "continuous-discovery-v2",
            "run-report-only",
            "--packet",
            "/tmp/packet.json",
            "--approval-reference",
            "approved-live-run",
            "--history-root",
            "/tmp/history",
            "--verdict",
            "/tmp/verdict.json",
        ]
    )
    assert parsed.history_roots == ["/tmp/history"]
    assert (
        parser.parse_args(
            ["continuous-discovery-v2", "run-register"]
        ).continuous_discovery_v2_command
        == "run-register"
    )


def test_cli_delegates_once_and_maps_runtime_result(capsys) -> None:  # type: ignore[no-untyped-def]
    calls: list[object] = []

    def runtime(args: object, **_injected: object) -> RuntimeResult:
        calls.append(args)
        return RuntimeResult(
            {"schema_version": "continuous-discovery-v2-result-v1", "result": "blocked"}, 2
        )

    args = Namespace(continuous_discovery_v2_command="run-register")
    assert run_continuous_discovery_v2(args, runtime=runtime) == 2
    assert calls == [args]
    assert '"result":"blocked"' in capsys.readouterr().out

def test_authorized_report_only_uses_existing_gate_c_boundary() -> None:
    from role_radar.continuous_acquisition.runtime_discovery_v2 import (
        run_continuous_discovery_v2,
    )

    args = Namespace(
        continuous_discovery_v2_command="run-report-only",
        packet="/tmp/packet.json",
        approval_reference="approved-live-run",
        repo=".",
        history_roots=["/tmp/history"],
        verdict="/tmp/verdict.json",
        policy="/etc/role-radar/discovery-policy.toml",
        acquisition_config="/etc/role-radar/acquisition.toml",
        database_url=None,
        acknowledgement=None,
        manual_canary=False,
        scheduled=False,
    )
    calls: list[object] = []

    def live_runner(received: object) -> object:
        calls.append(received)
        return {"result": "completed", "gate": "C", "downstream": "disabled"}

    result = run_continuous_discovery_v2(args, authorized_live_runner=live_runner)
    assert result.exit_code == 0
    assert result.payload["result"] == "completed"
    assert result.payload["schema_version"] == "continuous-discovery-v2-result-v1"
    assert calls == [args]


def test_register_mode_remains_hard_blocked() -> None:
    from role_radar.continuous_acquisition.runtime_discovery_v2 import (
        DISCOVERY_V2_LIVE_GATE_BLOCKED,
        run_continuous_discovery_v2,
    )

    result = run_continuous_discovery_v2(
        Namespace(continuous_discovery_v2_command="run-register")
    )
    assert result.exit_code == 2
    assert result.payload["code"] == DISCOVERY_V2_LIVE_GATE_BLOCKED
