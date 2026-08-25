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
            ["continuous-discovery-v2", "prepare-report-only"]
        ).continuous_discovery_v2_command
        == "prepare-report-only"
    )
    assert (
        parser.parse_args(
            ["continuous-discovery-v2", "run-report-only"]
        ).continuous_discovery_v2_command
        == "run-report-only"
    )
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
