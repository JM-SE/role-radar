"""Offline Gate B packet validation.

Gate B only answers whether an explicitly supplied packet is internally usable
for a later authorization decision.  It never creates authority, seeds,
roots, namespaces, or runtime state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from role_radar.evaluation.filesystem import FilesystemError, bounded_read_cli
from role_radar.evaluation.profile_relevant_acquisition.policy import (
    MAX_PER_BOARD_CAP,
    validate_hash,
    validate_seed_pair,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    NAMESPACE_RE,
    SYNTHETIC_FORBIDDEN_ROOTS,
)

SCHEMA_VERSION: Final[str] = "f10.1f-gate-b-packet-v1"
RESULT_READY: Final[Literal["ready"]] = "ready"
RESULT_BLOCKED: Final[Literal["blocked"]] = "blocked"
COMMIT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
MAX_PACKET_BYTES: Final[int] = 128 * 1024
MAX_BUDGET: Final[int] = 1_000_000
MAX_WINDOW_DAYS: Final[int] = 366

PACKET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "code_commit_sha256",
        "namespace",
        "root",
        "selection_seed",
        "partition_seed",
        "seed_origin",
        "seed_generated",
        "profile_id",
        "profile_version",
        "profile_sha256",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "window_start_utc",
        "window_end_utc",
        "per_board_cap",
        "per_company_cap",
        "corpus_count",
        "pilot_count",
        "holdout_count",
        "budget_units",
        "historical_reference",
        "authority_reference",
    }
)


class GateBPreflightError(ValueError):
    """Stable, sanitized Gate B failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GateBPacket:
    """All Gate B values are explicit; no field has an execution default."""

    code_commit_sha256: str
    namespace: str
    root: str
    selection_seed: str
    partition_seed: str
    seed_origin: str
    seed_generated: bool
    profile_id: str
    profile_version: str
    profile_sha256: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    window_start_utc: str
    window_end_utc: str
    per_board_cap: int
    per_company_cap: int
    corpus_count: int
    pilot_count: int
    holdout_count: int
    budget_units: int
    historical_reference: bool
    authority_reference: str

    def __post_init__(self) -> None:
        _validate_packet(self)

    def payload(self) -> dict[str, object]:
        return {
            "authority_reference": self.authority_reference,
            "budget_units": self.budget_units,
            "code_commit_sha256": self.code_commit_sha256,
            "corpus_count": self.corpus_count,
            "historical_reference": self.historical_reference,
            "holdout_count": self.holdout_count,
            "namespace": self.namespace,
            "partition_seed": self.partition_seed,
            "per_board_cap": self.per_board_cap,
            "per_company_cap": self.per_company_cap,
            "pilot_count": self.pilot_count,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "policy_version": self.policy_version,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "profile_version": self.profile_version,
            "root": self.root,
            "seed_generated": self.seed_generated,
            "seed_origin": self.seed_origin,
            "selection_seed": self.selection_seed,
            "window_end_utc": self.window_end_utc,
            "window_start_utc": self.window_start_utc,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Sanitized Gate B result; packet contents are never echoed."""

    result: Literal["ready", "blocked"]
    code: str
    code_commit_sha256: str | None = None
    profile_sha256: str | None = None
    policy_sha256: str | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "result": self.result,
            "schema_version": SCHEMA_VERSION,
        }
        if self.result == RESULT_READY:
            payload.update(
                {
                    "code_commit_sha256": self.code_commit_sha256,
                    "policy_sha256": self.policy_sha256,
                    "profile_sha256": self.profile_sha256,
                }
            )
        return payload


def canonical_packet_bytes(packet: GateBPacket) -> bytes:
    return json.dumps(
        packet.payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def build_packet_bytes(packet: GateBPacket) -> bytes:
    """Serialize a validated packet for explicit offline fixtures."""

    return canonical_packet_bytes(packet)


def load_packet_bytes(raw: bytes) -> GateBPacket:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PACKET_BYTES:
        raise GateBPreflightError("packet_size_invalid")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateBPreflightError("packet_encoding_invalid") from exc
    if not isinstance(parsed, dict) or set(parsed) != PACKET_KEYS:
        raise GateBPreflightError("packet_fields_invalid")
    try:
        values = dict(parsed)
        values.pop("schema_version")
        packet = GateBPacket(**values)
    except (TypeError, GateBPreflightError) as exc:
        if isinstance(exc, GateBPreflightError):
            raise
        raise GateBPreflightError("packet_fields_invalid") from exc
    if canonical_packet_bytes(packet) != raw:
        raise GateBPreflightError("packet_canonical_mismatch")
    return packet


def load_packet_file(*, path: Path, artifact_root: Path) -> GateBPacket:
    """Read exactly one packet below an existing, explicit artifact root."""

    try:
        raw = bounded_read_cli(path, artifact_root=artifact_root, max_bytes=MAX_PACKET_BYTES)
    except FilesystemError as exc:
        raise GateBPreflightError("packet_file_invalid") from exc
    return load_packet_bytes(raw)


def run_gate_b_preflight(*, path: Path | None, artifact_root: Path | None) -> PreflightReport:
    """Return a sanitized readiness report without any mutation or runtime IO."""

    try:
        if not isinstance(path, Path) or not isinstance(artifact_root, Path):
            raise GateBPreflightError("packet_file_required")
        packet = load_packet_file(path=path, artifact_root=artifact_root)
        if packet.root != str(artifact_root):
            raise GateBPreflightError("packet_root_mismatch")
        return PreflightReport(
            result=RESULT_READY,
            code="gate_b_packet_ready",
            code_commit_sha256=packet.code_commit_sha256,
            profile_sha256=packet.profile_sha256,
            policy_sha256=packet.policy_sha256,
        )
    except GateBPreflightError as exc:
        return PreflightReport(result=RESULT_BLOCKED, code=exc.code)


def _validate_packet(packet: GateBPacket) -> None:
    if (
        not isinstance(packet.code_commit_sha256, str)
        or COMMIT_RE.fullmatch(packet.code_commit_sha256) is None
    ):
        raise GateBPreflightError("commit_identity_invalid")
    if not isinstance(packet.namespace, str) or NAMESPACE_RE.fullmatch(packet.namespace) is None:
        raise GateBPreflightError("namespace_invalid")
    _validate_root(packet.root)
    try:
        validate_seed_pair(packet.selection_seed, packet.partition_seed)
    except ValueError as exc:
        raise GateBPreflightError(getattr(exc, "code", "seed_invalid")) from exc
    if packet.seed_origin != "operator_supplied" or packet.seed_generated is not False:
        raise GateBPreflightError("seed_origin_invalid")
    for field in ("profile_id", "profile_version", "policy_id", "policy_version"):
        value = getattr(packet, field)
        if not isinstance(value, str) or not value.strip() or any(char.isspace() for char in value):
            raise GateBPreflightError(f"{field}_invalid")
    try:
        validate_hash(packet.profile_sha256, code="profile_hash_invalid")
        validate_hash(packet.policy_sha256, code="policy_hash_invalid")
    except ValueError as exc:
        raise GateBPreflightError(getattr(exc, "code", "identity_hash_invalid")) from exc
    _validate_window(packet.window_start_utc, packet.window_end_utc)
    _validate_counts(packet)
    if packet.historical_reference is not False:
        raise GateBPreflightError("historical_reference_rejected")
    if packet.authority_reference != "new_planned_packet":
        raise GateBPreflightError("authority_reference_rejected")
    historical_marker = "2026" + "-08-25"
    if historical_marker in packet.authority_reference:
        raise GateBPreflightError("historical_reference_rejected")


def _validate_root(root: object) -> None:
    if not isinstance(root, str) or not root.startswith("/"):
        raise GateBPreflightError("root_invalid")
    root_path = Path(root)
    if any(part in {".", "..", ""} for part in root_path.parts):
        raise GateBPreflightError("root_invalid")
    if any(root == prefix or root.startswith(prefix + "/") for prefix in SYNTHETIC_FORBIDDEN_ROOTS):
        raise GateBPreflightError("root_production_rejected")


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise GateBPreflightError(f"{field}_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateBPreflightError(f"{field}_invalid") from exc
    if parsed.tzinfo != UTC:
        raise GateBPreflightError(f"{field}_invalid")
    return parsed


def _validate_window(start: object, end: object) -> None:
    start_at = _parse_utc(start, "window_start")
    end_at = _parse_utc(end, "window_end")
    if not start_at < end_at or (end_at - start_at).days > MAX_WINDOW_DAYS:
        raise GateBPreflightError("window_invalid")


def _validate_counts(packet: GateBPacket) -> None:
    values = {
        "per_board_cap": packet.per_board_cap,
        "per_company_cap": packet.per_company_cap,
        "corpus_count": packet.corpus_count,
        "pilot_count": packet.pilot_count,
        "holdout_count": packet.holdout_count,
        "budget_units": packet.budget_units,
    }
    for field, value in values.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise GateBPreflightError(f"{field}_invalid")
    if packet.per_board_cap == 0 or packet.per_board_cap > MAX_PER_BOARD_CAP:
        raise GateBPreflightError("per_board_cap_invalid")
    if packet.per_company_cap == 0 or packet.per_company_cap > MAX_PER_BOARD_CAP:
        raise GateBPreflightError("per_company_cap_invalid")
    if packet.corpus_count == 0 or packet.pilot_count + packet.holdout_count != packet.corpus_count:
        raise GateBPreflightError("cardinality_invalid")
    if packet.budget_units == 0 or packet.budget_units > MAX_BUDGET:
        raise GateBPreflightError("budget_invalid")


__all__ = [
    "MAX_PACKET_BYTES",
    "SCHEMA_VERSION",
    "GateBPacket",
    "GateBPreflightError",
    "PreflightReport",
    "build_packet_bytes",
    "canonical_packet_bytes",
    "load_packet_bytes",
    "load_packet_file",
    "run_gate_b_preflight",
]
