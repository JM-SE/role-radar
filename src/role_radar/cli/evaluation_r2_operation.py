"""Lazy, BLOCK-0-only adapter for future R2 operational authorization."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from typing import Any, cast

SCHEMA_VERSION = "r2-operation-cli-v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")


def canonical_confirmation_challenge(
    *, packet_digest: str, gate: str, expires_at: str, nonce: str, operation_id: str
) -> str:
    """Return the only confirmation spelling accepted by the future injected seam."""
    if _HEX64.fullmatch(packet_digest) is None or gate not in {"c", "post-c", "d", "e", "f"}:
        raise ValueError("confirmation_invalid")
    if (
        not isinstance(expires_at, str)
        or not expires_at
        or not _ID.fullmatch(nonce)
        or not _ID.fullmatch(operation_id)
    ):
        raise ValueError("confirmation_invalid")
    payload = (
        f"r2-operation-confirm-v1\0{packet_digest}\0{gate}\0{expires_at}\0{nonce}\0{operation_id}"
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def validate_confirmation(*, supplied: str | None, expected: str) -> None:
    if (
        supplied is None
        or _HEX64.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, expected)
    ):
        raise ValueError("confirmation_invalid")


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
        command.add_argument("--packet-ref", metavar="REF")
        command.add_argument("--approval-ref", metavar="REF")
        command.add_argument("--confirmation")
    return cast(argparse.ArgumentParser, parent)


def run(args: argparse.Namespace) -> int:
    # References are intentionally not opened: no packet/approval can be
    # implicitly trusted by this adapter, and this implementation has no live capability.
    # There is no packet decoder or production root in this namespace yet.  A
    # prepared/injected caller may validate a challenge, but this CLI remains
    # BLOCK-0 and never reaches a service or provider.
    if getattr(args, "confirmation", None) is not None:
        try:
            validate_confirmation(supplied=args.confirmation, expected="0" * 64)
        except ValueError:
            code = "confirmation_invalid"
        else:
            code = "BLOCK-0"
    else:
        # Preserve the established pre-capability BLOCK-0 response while the
        # external packet decoder remains intentionally unavailable.
        code = "BLOCK-0"
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "command": args.r2_operation_command,
                "result": "blocked",
                "code": code,
            },
            separators=(",", ":"),
        )
    )
    return 2


__all__ = ["canonical_confirmation_challenge", "register_parser", "run", "validate_confirmation"]
