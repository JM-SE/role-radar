"""Thin CLI adapter for the dedicated continuous-discovery-v2 command."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from typing import Any, cast

from role_radar.continuous_acquisition import runtime_discovery_v2
from role_radar.continuous_acquisition.runtime_discovery_v2 import (
    EXIT_BLOCKED,
    EXIT_INTERNAL,
    RuntimeCompositionError,
    RuntimeResult,
)


def _payload(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def register_continuous_discovery_v2_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Register only syntax; all behavior is delegated to the v2 runtime."""

    parser = cast(argparse.ArgumentParser, subparsers.add_parser("continuous-discovery-v2"))
    commands = parser.add_subparsers(dest="continuous_discovery_v2_command", required=True)
    commands.add_parser("plan")
    prepare = commands.add_parser("prepare-report-only")
    prepare.add_argument("--operation-id")

    for command, mode in (
        (commands.add_parser("run-report-only"), "report_only"),
        (commands.add_parser("run-register"), "register"),
    ):
        command.set_defaults(continuous_discovery_v2_mode=mode)
        command.add_argument("--operation-id")
        # These options are accepted only so a caller cannot turn an old
        # acknowledgement/scheduling switch into a v2 capability.
        command.add_argument("--acknowledgement")
        command.add_argument("--manual-canary", action="store_true")
        command.add_argument("--scheduled", action="store_true")
    return parser


def _result(value: object) -> RuntimeResult:
    if isinstance(value, RuntimeResult):
        return value
    if isinstance(value, dict):
        return RuntimeResult(value, EXIT_BLOCKED)
    raise RuntimeCompositionError("internal_error", exit_code=EXIT_INTERNAL)


def run_continuous_discovery_v2(
    args: Any,
    *,
    runtime: Callable[..., object] = runtime_discovery_v2.run_continuous_discovery_v2,
    **injected: object,
) -> int:
    """Delegate once and expose only the bounded JSON/exit-code contract."""

    try:
        result = _result(runtime(args, **injected))
        print(_payload(result.payload))
        return result.exit_code
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
