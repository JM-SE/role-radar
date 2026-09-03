"""Lazy, BLOCK-0-only adapter for future R2 operational authorization."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from datetime import UTC
from typing import Any, cast

from role_radar.evaluation.r2_operational_authorization import OperationPacket

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


def validate_packet_confirmation(
    *, packet: OperationPacket, supplied: str | None, operation_id: str | None = None
) -> None:
    """Validate the canonical challenge at the injected offline boundary."""
    expected = canonical_confirmation_challenge(
        packet_digest=packet.packet_sha256,
        gate=packet.gate,
        expires_at=packet.expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        nonce=packet.replay_nonce,
        operation_id=operation_id or packet.operation_id,
    )
    validate_confirmation(supplied=supplied, expected=expected)


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
    # No packet decoder exists in this intentionally inert CLI boundary. A
    # supplied confirmation therefore cannot be accepted or ignored.
    code = "confirmation_invalid" if getattr(args, "confirmation", None) is not None else "BLOCK-0"
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
