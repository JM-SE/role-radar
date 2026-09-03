"""Lazy, BLOCK-0-only adapter for future R2 operational authorization."""

from __future__ import annotations

import argparse
import json
from typing import Any, cast

SCHEMA_VERSION = "r2-operation-cli-v1"


def register_parser(subparsers: Any) -> argparse.ArgumentParser:
    parent = subparsers.add_parser("r2-operation")
    commands = parent.add_subparsers(dest="r2_operation_command", required=True)
    for name in (
        "prepare",
        "status",
        "execute-c",
        "execute-post-c",
        "execute-d",
        "execute-e",
        "execute-f",
    ):
        command = commands.add_parser(name)
        command.add_argument("--packet-ref")
        command.add_argument("--approval-ref")
        command.add_argument("--confirmation")
    return cast(argparse.ArgumentParser, parent)


def run(args: argparse.Namespace) -> int:
    # References are intentionally not opened: no packet/approval can be
    # implicitly trusted by this adapter, and this implementation has no live capability.
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "command": args.r2_operation_command,
                "result": "blocked",
                "code": "BLOCK-0",
            },
            separators=(",", ":"),
        )
    )
    return 2


__all__ = ["register_parser", "run"]
