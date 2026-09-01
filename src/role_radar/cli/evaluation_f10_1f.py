"""Thin, fail-closed CLI boundary for the F10.1F transition graph.

This module deliberately has no F10.1F runtime imports.  The live gates are
not enabled by this change: until separately approved, exact gate-local
acknowledgements and production artifacts exist, every gate command stops at
BLOCK-0 before a delegate can be reached.

The adapter owns syntax and the stable, sanitized terminal protocol only.  It
must remain safe to import while settings, database, filesystem, network, and
holdout access are unavailable.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, cast

SCHEMA_VERSION: Final[str] = "f10.1f-cli-v1"
BLOCK_0: Final[str] = "BLOCK-0"
LIVE_EXECUTION_DISABLED: Final[str] = "f10_1f_live_execution_disabled"
PRODUCTION_ARTIFACTS_REQUIRED: Final[str] = "f10_1f_production_artifacts_required"
DATASET_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$", re.ASCII)

GATED_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "run-report-only",
        "preregister",
        "acquire",
        "preview",
        "freeze",
    }
)


def _payload(command: str, result: str, code: str, **fields: object) -> str:
    """Serialize only the public F10.1F CLI envelope."""

    value: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "result": result,
        "code": code,
    }
    value.update(fields)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _print_block(command: str, code: str = BLOCK_0, **fields: object) -> int:
    print(_payload(command, "blocked", code, **fields))
    return 2


def register_f10_1f_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the F10.1F syntax exactly once on the supplied parser.

    Gate acknowledgements are intentionally optional at the argparse layer.
    A missing acknowledgement is a protocol BLOCK-0, rather than an argparse
    error, so it cannot be confused with a syntax failure or reach a gate
    body.  The live commands also accept no generic confirmation escape
    hatch.
    """

    parent = cast(argparse.ArgumentParser, subparsers.add_parser("f10-1f"))
    commands = parent.add_subparsers(dest="f10_1f_command", required=True)

    provenance = commands.add_parser("provenance")
    provenance.add_argument("--file")
    provenance.add_argument("--artifact-root")
    commands.add_parser("status")

    verify = commands.add_parser("verify")
    verify.add_argument("--dataset-id")

    for name in sorted(GATED_COMMANDS):
        command = commands.add_parser(name)
        command.add_argument("--acknowledgement")
        command.add_argument("--operation-id")
        command.add_argument("--lineage-id")
        # These are binding inputs, not execution switches.  They are parsed
        # for forward-compatible command contracts but are never read while
        # the live gate remains disabled.
        command.add_argument("--artifact")
        command.add_argument("--file")
        command.add_argument("--dataset-id")

    return parent


def _run_provenance(args: Any) -> int:
    """Verify an explicitly supplied artifact without exposing its contents."""

    filename = getattr(args, "file", None)
    if filename is not None:
        try:
            artifact_root = getattr(args, "artifact_root", None)
            if not isinstance(artifact_root, str) or not artifact_root:
                return _print_block("provenance", "artifact_root_required")
            from role_radar.evaluation.filesystem import bounded_read_cli
            from role_radar.evaluation.profile_relevant_acquisition.provenance_loader import (
                ProvenanceLoadError,
                load_provenance_bytes,
            )

            artifact = load_provenance_bytes(
                bounded_read_cli(Path(filename), artifact_root=Path(artifact_root))
            )
            if artifact.artifact_class.value != "approved_production":
                return _print_block("provenance", "artifact_class_not_approved")
            print(
                _payload(
                    "provenance",
                    "verified",
                    "provenance_verified",
                    provenance_sha256=artifact.provenance_sha256,
                )
            )
            return 0
        except (OSError, ProvenanceLoadError, ValueError, TypeError):
            return _print_block("provenance", "provenance_invalid")

    print(
        _payload(
            "provenance",
            "offline",
            "provenance_not_loaded",
            live_execution="disabled",
        )
    )
    return 0


def _run_status(_args: Any) -> int:
    """Report gate state without constructing any runtime or store."""

    print(
        _payload(
            "status",
            "offline_status",
            "live_execution_disabled",
            gates={name: "disabled" for name in ("C", "D", "E", "F")},
        )
    )
    return 0


def _run_verify(args: Any) -> int:
    """Validate only the public dataset-id shape; never open a store.

    Actual artifact verification is a live-root operation and remains
    disabled.  Shape validation makes malformed input deterministic without
    leaking paths or touching the filesystem.
    """

    dataset_id = getattr(args, "dataset_id", None)
    if dataset_id is not None and not DATASET_ID_RE.fullmatch(dataset_id):
        return _run_blocked_verify("dataset_id_invalid")
    return _run_blocked_verify(PRODUCTION_ARTIFACTS_REQUIRED)


def _run_blocked_verify(code: str) -> int:
    print(_payload("verify", "blocked", code))
    return 2


def _run_gated_placeholder(args: Any) -> int:
    """Fail before all downstream calls for every currently gated command.

    Do not inspect or normalize the acknowledgement here.  Without the
    separately approved artifact-backed challenge verifier, a supplied value
    cannot be known to be current, local, and gate-specific.  Treating every
    value as BLOCK-0 is the only safe transition-matrix behavior and ensures
    stale, malformed, wrong-gate, and cross-lineage values are equivalent.
    """

    command = cast(str, getattr(args, "f10_1f_command", "unknown"))
    if command not in GATED_COMMANDS:
        return _run_blocked_verify("command_invalid")
    return _print_block(command, live_execution="disabled")


def run(args: Any) -> int:
    """Dispatch one command without importing or calling a downstream gate."""

    command = cast(str, getattr(args, "f10_1f_command", "unknown"))
    handlers: dict[str, Callable[[Any], int]] = {
        "provenance": _run_provenance,
        "status": _run_status,
        "verify": _run_verify,
    }
    handler = handlers.get(command)
    if handler is not None:
        return handler(args)
    return _run_gated_placeholder(args)


register_parser = register_f10_1f_parser

__all__ = [
    "BLOCK_0",
    "GATED_COMMANDS",
    "LIVE_EXECUTION_DISABLED",
    "PRODUCTION_ARTIFACTS_REQUIRED",
    "register_f10_1f_parser",
    "register_parser",
    "run",
]
