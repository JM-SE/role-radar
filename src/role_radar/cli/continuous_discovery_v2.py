"""Thin CLI adapter for the dedicated continuous-discovery-v2 command."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from typing import Any, cast


def _payload(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def register_continuous_discovery_v2_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Register v2 syntax, including the explicit Gate C live boundary."""

    parser = cast(argparse.ArgumentParser, subparsers.add_parser("continuous-discovery-v2"))
    commands = parser.add_subparsers(dest="continuous_discovery_v2_command", required=True)
    commands.add_parser("plan")
    prepare = commands.add_parser("prepare-report-only")
    prepare.add_argument("--operation-id")

    run_report = commands.add_parser("run-report-only")
    run_report.set_defaults(continuous_discovery_v2_mode="report_only")
    run_report.add_argument("--operation-id")
    run_report.add_argument("--packet", required=True)
    run_report.add_argument("--approval-reference", required=True)
    run_report.add_argument("--repo", default=".")
    run_report.add_argument("--history-root", action="append", dest="history_roots", required=True)
    run_report.add_argument("--verdict", required=True)
    run_report.add_argument("--policy", default="/etc/role-radar/discovery-policy.toml")
    run_report.add_argument("--acquisition-config", default="/etc/role-radar/acquisition.toml")
    run_report.add_argument("--database-url")
    run_report.add_argument("--acknowledgement")
    run_report.add_argument("--manual-canary", action="store_true")
    run_report.add_argument("--scheduled", action="store_true")
    run_register = commands.add_parser("run-register")
    run_register.set_defaults(continuous_discovery_v2_mode="register")
    run_register.add_argument("--operation-id")
    run_register.add_argument("--acknowledgement")
    run_register.add_argument("--manual-canary", action="store_true")
    run_register.add_argument("--scheduled", action="store_true")
    return parser


def _result(value: object) -> Any:
    from role_radar.continuous_acquisition.runtime_discovery_v2 import RuntimeResult

    if isinstance(value, RuntimeResult):
        return value
    if isinstance(value, dict):
        return RuntimeResult(value, 2)
    from role_radar.continuous_acquisition.runtime_discovery_v2 import RuntimeCompositionError

    raise RuntimeCompositionError("internal_error", exit_code=1)


def run_continuous_discovery_v2(
    args: Any,
    *,
    runtime: Callable[..., object] | None = None,
    **injected: object,
) -> int:
    """Delegate once and expose only the bounded JSON/exit-code contract."""

    if runtime is None:
        from role_radar.continuous_acquisition.runtime_discovery_v2 import (
            run_continuous_discovery_v2 as runtime,
        )
    from role_radar.continuous_acquisition.runtime_discovery_v2 import (
        EXIT_INTERNAL,
        RuntimeCompositionError,
    )

    assert runtime is not None
    try:
        result = _result(runtime(args, **injected))
        print(_payload(result.payload))
        return int(result.exit_code)
    except RuntimeCompositionError as exc:
        print(
            _payload(
                {
                    "schema_version": "continuous-discovery-v2-result-v1",
                    "result": "blocked",
                    "code": exc.code,
                }
            )
        )
        return exc.exit_code
    except Exception:
        print(
            _payload(
                {
                    "schema_version": "continuous-discovery-v2-result-v1",
                    "result": "blocked",
                    "code": "internal_error",
                }
            )
        )
        return EXIT_INTERNAL


run = run_continuous_discovery_v2
register_parser = register_continuous_discovery_v2_parser


__all__ = [
    "register_continuous_discovery_v2_parser",
    "register_parser",
    "run",
    "run_continuous_discovery_v2",
]
