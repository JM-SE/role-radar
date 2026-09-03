"""Pure, fail-closed authorization contracts for the future R2 operation.

This module intentionally has no filesystem, network, settings, or provider
imports.  Approval is an assertion made by an injected, independent verifier;
this module never issues or self-approves one.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

HASH_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
GATES = frozenset({"c", "post-c", "d", "e", "f"})
PUBLIC_CODES = frozenset(
    {
        "malformed_packet",
        "operation_mismatch",
        "gate_mismatch",
        "binding_mismatch",
        "approval_required",
        "approval_invalid",
        "expired",
        "replay",
        "predecessor_missing",
        "capability_mismatch",
        "confirmation_required",
        "blocked",
    }
)


class AuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code if code in PUBLIC_CODES else "blocked"
        super().__init__(self.code)


class ExternalApprovalVerifier(Protocol):
    """Independent approval boundary. Implementations must live outside DTOs."""

    def verify(self, packet: "OperationPacket", approval_reference: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class GateAuthorization:
    gate: str
    packet_hash: str
    approval_reference: str
    predecessor_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperationPacket:
    operation_id: str
    gate: str
    commit_sha256: str
    source_plan_sha256: str
    b_ready_sha256: str
    profile_sha256: str
    policy_sha256: str
    query_plan_sha256: str
    destination_namespace: str
    destination_root: str
    window_start: datetime
    window_cutoff: datetime
    selection_seed_sha256: str
    partition_seed_sha256: str
    source_cap: int
    quota: int
    cardinality: int
    budget: int
    capability_name: str
    approval_reference: str
    approval_sha256: str
    expires_at: datetime
    replay_nonce: str
    predecessor_hashes: tuple[str, ...]

    def canonical_dict(self) -> dict[str, object]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        for key in ("window_start", "window_cutoff", "expires_at"):
            value[key] = getattr(self, key).astimezone(UTC).isoformat().replace("+00:00", "Z")
        value["predecessor_hashes"] = list(self.predecessor_hashes)
        return value

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode()

    @property
    def packet_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def authorization(self) -> GateAuthorization:
        return GateAuthorization(
            self.gate, self.packet_sha256, self.approval_reference, self.predecessor_hashes
        )


def _hash(value: object) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise AuthorizationError("malformed_packet")
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise AuthorizationError("malformed_packet")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError("malformed_packet") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError("malformed_packet")
    return parsed.astimezone(UTC)


def parse_operation_packet(value: object) -> OperationPacket:
    if not isinstance(value, dict):
        raise AuthorizationError("malformed_packet")
    names = set(OperationPacket.__dataclass_fields__)
    if set(value) != names:
        raise AuthorizationError("malformed_packet")
    try:
        packet = OperationPacket(
            operation_id=value["operation_id"],
            gate=value["gate"],
            commit_sha256=_hash(value["commit_sha256"]),
            source_plan_sha256=_hash(value["source_plan_sha256"]),
            b_ready_sha256=_hash(value["b_ready_sha256"]),
            profile_sha256=_hash(value["profile_sha256"]),
            policy_sha256=_hash(value["policy_sha256"]),
            query_plan_sha256=_hash(value["query_plan_sha256"]),
            destination_namespace=value["destination_namespace"],
            destination_root=value["destination_root"],
            window_start=_time(value["window_start"]),
            window_cutoff=_time(value["window_cutoff"]),
            selection_seed_sha256=_hash(value["selection_seed_sha256"]),
            partition_seed_sha256=_hash(value["partition_seed_sha256"]),
            source_cap=value["source_cap"],
            quota=value["quota"],
            cardinality=value["cardinality"],
            budget=value["budget"],
            capability_name=value["capability_name"],
            approval_reference=value["approval_reference"],
            approval_sha256=_hash(value["approval_sha256"]),
            expires_at=_time(value["expires_at"]),
            replay_nonce=value["replay_nonce"],
            predecessor_hashes=tuple(value["predecessor_hashes"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorizationError("malformed_packet") from exc
    if packet.gate not in GATES or packet.selection_seed_sha256 == packet.partition_seed_sha256:
        raise AuthorizationError("malformed_packet")
    if not all(
        isinstance(getattr(packet, name), str) and getattr(packet, name).strip()
        for name in (
            "operation_id",
            "destination_namespace",
            "destination_root",
            "capability_name",
            "approval_reference",
            "replay_nonce",
        )
    ):
        raise AuthorizationError("malformed_packet")
    if not all(
        isinstance(getattr(packet, name), int)
        and not isinstance(getattr(packet, name), bool)
        and getattr(packet, name) >= 0
        for name in ("source_cap", "quota", "cardinality", "budget")
    ):
        raise AuthorizationError("malformed_packet")
    if (
        packet.window_start >= packet.window_cutoff
        or not packet.predecessor_hashes
        or any(
            not isinstance(x, str) or HASH_RE.fullmatch(x) is None
            for x in packet.predecessor_hashes
        )
    ):
        raise AuthorizationError("malformed_packet")
    return packet


def authorize_packet(
    packet: OperationPacket,
    verifier: ExternalApprovalVerifier,
    *,
    now: datetime,
    expected_gate: str | None = None,
    predecessor_hashes: tuple[str, ...] | None = None,
    capability_name: str | None = None,
    used_nonces: frozenset[str] = frozenset(),
) -> GateAuthorization:
    if expected_gate is not None and packet.gate != expected_gate:
        raise AuthorizationError("gate_mismatch")
    if packet.replay_nonce in used_nonces:
        raise AuthorizationError("replay")
    current = now.astimezone(UTC)
    if (
        current >= packet.expires_at
        or current < packet.window_start
        or current > packet.window_cutoff
    ):
        raise AuthorizationError("expired")
    if predecessor_hashes is not None and tuple(packet.predecessor_hashes) != tuple(
        predecessor_hashes
    ):
        raise AuthorizationError("predecessor_missing")
    if capability_name is not None and packet.capability_name != capability_name:
        raise AuthorizationError("capability_mismatch")
    try:
        valid = verifier.verify(packet, packet.approval_reference)
    except Exception:
        valid = False
    if valid is not True:
        raise AuthorizationError("approval_invalid")
    return packet.authorization()


__all__ = [
    "AuthorizationError",
    "ExternalApprovalVerifier",
    "GateAuthorization",
    "OperationPacket",
    "authorize_packet",
    "parse_operation_packet",
]
