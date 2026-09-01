"""Pure, fail-closed authorization contracts for offline R2 Gate C."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    canonical_packet_bytes,
)

SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
GATE_C_AUTH_SCHEMA: Final[str] = "f10.1f-gate-c-authorization-v1"


class GateCAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def gate_b_packet_sha256(packet: GateBPacket) -> str:
    return hashlib.sha256(canonical_packet_bytes(packet)).hexdigest()


def _hash(value: object, code: str) -> None:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise GateCAuthorizationError(code)


def _id(value: object, code: str) -> None:
    if type(value) is not str or ID_RE.fullmatch(value) is None:
        raise GateCAuthorizationError(code)


def _utc(value: object, code: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise GateCAuthorizationError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateCAuthorizationError(code) from exc
    if parsed.tzinfo is not UTC:
        raise GateCAuthorizationError(code)
    return parsed


def _root(value: object) -> None:
    if type(value) is not str or not value.startswith("/"):
        raise GateCAuthorizationError("gate_c_root_invalid")
    path = Path(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise GateCAuthorizationError("gate_c_root_invalid")
    forbidden = ("/opt", "/etc", "/var", "/usr", "/run", "/srv")
    if any(value == item or value.startswith(item + "/") for item in forbidden):
        raise GateCAuthorizationError("gate_c_root_rejected")


@dataclass(frozen=True, slots=True)
class AcceptedGateBBinding:
    packet: GateBPacket
    packet_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.packet, GateBPacket):
            raise GateCAuthorizationError("gate_b_packet_invalid")
        _hash(self.packet_sha256, "gate_b_packet_hash_invalid")
        if self.packet_sha256 != gate_b_packet_sha256(self.packet):
            raise GateCAuthorizationError("gate_b_packet_hash_mismatch")


@dataclass(frozen=True, slots=True)
class GateCProvenance:
    gate_b_packet_sha256: str
    candidate_commit_sha256: str
    profile_id: str
    profile_version: str
    profile_sha256: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    query_plan_sha256: str
    namespace: str
    approved_root: str
    window_start_utc: str
    window_end_utc: str
    cutoff_utc: str
    budget_units: int

    def __post_init__(self) -> None:
        _hash(self.gate_b_packet_sha256, "gate_b_packet_hash_invalid")
        _hash(self.candidate_commit_sha256, "candidate_commit_invalid")
        hashes = (
            (self.profile_sha256, "profile_hash_invalid"),
            (self.policy_sha256, "policy_hash_invalid"),
            (self.query_plan_sha256, "query_plan_hash_invalid"),
        )
        for value, code in hashes:
            _hash(value, code)
        identifiers = (
            (self.profile_id, "profile_id_invalid"),
            (self.profile_version, "profile_version_invalid"),
            (self.policy_id, "policy_id_invalid"),
            (self.policy_version, "policy_version_invalid"),
        )
        for value, code in identifiers:
            _id(value, code)
        _id(self.namespace, "namespace_invalid")
        _root(self.approved_root)
        window = (
            (self.window_start_utc, "window_start_invalid"),
            (self.window_end_utc, "window_end_invalid"),
            (self.cutoff_utc, "cutoff_invalid"),
        )
        start, end, cutoff = (_utc(value, code) for value, code in window)
        if not start < cutoff <= end:
            raise GateCAuthorizationError("window_invalid")
        if type(self.budget_units) is not int or self.budget_units <= 0:
            raise GateCAuthorizationError("budget_invalid")


@dataclass(frozen=True, slots=True)
class GateCAuthorization:
    gate: str
    mode: str
    report_only: bool
    operation_id: str
    lineage_id: str
    expires_at_utc: str
    provenance: GateCProvenance
    per_board_cap: int
    per_company_cap: int
    budget_units: int
    max_brave_requests: int
    max_tavily_requests: int
    max_board_candidates: int
    max_board_verifications: int
    max_wire_attempts: int
    artifact_class: str

    def __post_init__(self) -> None:
        if self.gate != "C" or self.mode != "report-only" or self.report_only is not True:
            raise GateCAuthorizationError("gate_c_mode_invalid")
        _id(self.operation_id, "operation_invalid")
        _id(self.lineage_id, "lineage_invalid")
        expiry = _utc(self.expires_at_utc, "authorization_expiry_invalid")
        if expiry <= datetime.now(UTC):
            raise GateCAuthorizationError("authorization_expired")
        if not isinstance(self.provenance, GateCProvenance):
            raise GateCAuthorizationError("provenance_invalid")
        if self.artifact_class != "offline_private_report_only":
            raise GateCAuthorizationError("artifact_class_invalid")
        values = (
            self.per_board_cap,
            self.per_company_cap,
            self.budget_units,
            self.max_brave_requests,
            self.max_tavily_requests,
            self.max_board_candidates,
            self.max_board_verifications,
            self.max_wire_attempts,
        )
        if any(type(value) is not int or value <= 0 for value in values):
            raise GateCAuthorizationError("budget_invalid")


_PROVENANCE_FIELDS = frozenset(GateCProvenance.__dataclass_fields__)
_AUTH_FIELDS = frozenset(GateCAuthorization.__dataclass_fields__) | {"schema_version"}


def parse_gate_c_authorization(value: object) -> GateCAuthorization:
    """Parse an artifact mapping with no coercion, defaults, or extra fields."""
    if not isinstance(value, Mapping) or set(value) != _AUTH_FIELDS:
        raise GateCAuthorizationError("authorization_fields_invalid")
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != _PROVENANCE_FIELDS:
        raise GateCAuthorizationError("provenance_fields_invalid")
    if value.get("schema_version") != GATE_C_AUTH_SCHEMA:
        raise GateCAuthorizationError("authorization_schema_invalid")
    try:
        parsed_provenance = GateCProvenance(**dict(provenance))
        fields = dict(value)
        fields.pop("schema_version")
        fields["provenance"] = parsed_provenance
        return GateCAuthorization(**fields)
    except GateCAuthorizationError:
        raise
    except (TypeError, ValueError) as exc:
        raise GateCAuthorizationError("authorization_fields_invalid") from exc


def authorize_gate_c(
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: object,
    *,
    now: datetime | None = None,
) -> None:
    """Compare every immutable binding before any effectful dependency is used."""
    if not isinstance(authorization, GateCAuthorization) or not isinstance(
        accepted_b, AcceptedGateBBinding
    ):
        raise GateCAuthorizationError("gate_c_authorization_required")
    check = datetime.now(UTC) if now is None else now.astimezone(UTC)
    if check >= _utc(authorization.expires_at_utc, "authorization_expiry_invalid"):
        raise GateCAuthorizationError("authorization_expired")
    packet = accepted_b.packet
    p = authorization.provenance
    comparisons = (
        (p.gate_b_packet_sha256, accepted_b.packet_sha256, "gate_b_packet_hash_mismatch"),
        (p.candidate_commit_sha256, packet.code_commit_sha256, "candidate_commit_mismatch"),
        (p.profile_id, packet.profile_id, "profile_id_mismatch"),
        (p.profile_version, packet.profile_version, "profile_version_mismatch"),
        (p.profile_sha256, packet.profile_sha256, "profile_hash_mismatch"),
        (p.policy_id, packet.policy_id, "policy_id_mismatch"),
        (p.policy_version, packet.policy_version, "policy_version_mismatch"),
        (p.policy_sha256, packet.policy_sha256, "policy_hash_mismatch"),
        (p.namespace, packet.namespace, "namespace_mismatch"),
        (p.approved_root, packet.root, "root_mismatch"),
        (p.window_start_utc, packet.window_start_utc, "window_mismatch"),
        (p.window_end_utc, packet.window_end_utc, "window_mismatch"),
        (authorization.per_board_cap, packet.per_board_cap, "budget_binding_mismatch"),
        (authorization.per_company_cap, packet.per_company_cap, "budget_binding_mismatch"),
        (authorization.budget_units, packet.budget_units, "budget_binding_mismatch"),
    )
    for expected, actual, code in comparisons:
        if expected != actual:
            raise GateCAuthorizationError(code)
    if getattr(plan, "plan_sha256", None) != p.query_plan_sha256:
        raise GateCAuthorizationError("query_plan_hash_mismatch")
    binding = getattr(plan, "profile_binding", None)
    if (
        getattr(binding, "profile_id", None) != p.profile_id
        or getattr(binding, "row_version", None) != p.profile_version
        or getattr(binding, "canonical_profile_sha256", None) != p.profile_sha256
    ):
        raise GateCAuthorizationError("profile_binding_mismatch")
    if (
        getattr(plan, "policy_version", None) != p.policy_version
        or getattr(plan, "policy_sha256", None) != p.policy_sha256
    ):
        raise GateCAuthorizationError("policy_binding_mismatch")
    limits = getattr(plan, "limits", {})
    expected_limits = (
        ("max_brave_requests_per_run", authorization.max_brave_requests),
        ("max_tavily_requests_per_run", authorization.max_tavily_requests),
        ("max_unique_board_candidates_per_run", authorization.max_board_candidates),
        ("max_unique_board_verifications_per_run", authorization.max_board_verifications),
        ("max_verification_wire_attempts_per_run", authorization.max_wire_attempts),
    )
    if any(limits.get(name) != value for name, value in expected_limits):
        raise GateCAuthorizationError("budget_binding_mismatch")


__all__ = [
    "AcceptedGateBBinding",
    "GateCAuthorization",
    "GateCAuthorizationError",
    "GateCProvenance",
    "authorize_gate_c",
    "gate_b_packet_sha256",
    "parse_gate_c_authorization",
]
