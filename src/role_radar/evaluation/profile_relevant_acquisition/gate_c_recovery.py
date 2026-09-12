"""Offline recovery of a bounded, partial Gate C discovery.

This module deliberately does not import providers, credentials, quota adapters,
or the live Gate C runner.  It consumes immutable report-only artifacts from a
previous operation and writes a new, isolated evidence root.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    MAX_OPERATION_ARTIFACT_BYTES,
    MAX_START_MARKER_BYTES,
    MAX_TERMINAL_REPORT_BYTES,
    DiscoveryArtifactError,
    ReportOnlyTerminalReportV1,
    ReportOnlyVerifiedSourceV1,
    canonical_artifact_json,
    loads_bounded_artifact,
    parse_start_marker,
    parse_terminal_report,
)
from role_radar.discovery.authorization_v2 import (
    DEFAULT_DISCOVERY_BUDGETS,
    DiscoveryOperationV2,
    OperationKind,
    ProviderQuotaContextV1,
    canonical_json_bytes,
    challenge_sha256,
)
from role_radar.discovery.policy import ProfileBindingV1
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    PACKET_KEYS as GATE_B_PACKET_KEYS,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    SCHEMA_VERSION as GATE_B_SCHEMA_VERSION,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    PreflightReport,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCProvenance,
    gate_b_packet_sha256,
)
from role_radar.evaluation.profile_relevant_acquisition.seed_inputs import SeedInputs
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    SourcePlan,
    SourcePlanBudget,
    build_source_plan,
)
from role_radar.sources.identity import canonical_source_key

MAX_RECOVERY_ARTIFACT_BYTES = 256 * 1024
MAX_RECOVERY_OUTPUT_BYTES = 64 * 1024
MAX_APPROVAL_REFERENCE_CHARS = 128
# Keep the recovery boundary independent from the planner/runtime import graph.
MAX_DISCOVERY_QUERIES = 4
MAX_DISCOVERY_PHRASES = 8
MAX_APPROVED_PHRASE_CHARS = 128
MAX_DISCOVERY_QUERY_CHARS = 2048
MAX_DISCOVERY_RESULTS_PER_QUERY = 10
MAX_BRAVE_REQUESTS_PER_RUN = 4
MAX_TAVILY_REQUESTS_PER_RUN = 4
MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN = 10
MAX_UNIQUE_BOARD_CANDIDATES_SEEN_PER_RUN = 100
MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN = 8
MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN = 100
MAX_VERIFIED_POSTINGS = 100_000
PACKET_QUOTA_CONFIG_VERSION = "config-v1"
PROVIDER_QUOTA_CONFIG_VERSION = "acquisition-v1"
_APPROVAL_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
RECOVERY_MANIFEST_SCHEMA = "f10.1f-gate-c-recovery-manifest-v1"
RECOVERY_VERDICT_SCHEMA = "f10.1f-gate-c-recovery-verdict-v1"
_PACKET_KEYS = {
    "approval_reference_NOT_GRANTED",
    "authorization",
    "capability_claims",
    "caps_budget",
    "derivation",
    "derived_code_commit_sha256",
    "gate_b_packet",
    "gate_b_packet_sha256",
    "gate_b_report",
    "git_sha",
    "plan_sha256",
    "quota",
    "revision",
    "seed_origin",
    "window",
}
_AUTH_KEYS = {
    "schema_version",
    "artifact_class",
    "budget_units",
    "expires_at_utc",
    "gate",
    "lineage_id",
    "max_board_candidates",
    "max_board_verifications",
    "max_brave_requests",
    "max_tavily_requests",
    "max_wire_attempts",
    "mode",
    "operation_id",
    "per_board_cap",
    "per_company_cap",
    "provenance",
    "report_only",
}
_PROVENANCE_KEYS = set(GateCProvenance.__dataclass_fields__)
_OPERATION_KEYS = {
    "authorization_expires_at_utc",
    "authorization_max_ttl_seconds",
    "budgets",
    "challenge_nonce",
    "challenge_sha256",
    "created_at_utc",
    "destinations",
    "operation_id",
    "operation_kind",
    "operation_sha256",
    "plan_identity",
    "policy_identity",
    "profile_binding",
    "providers",
    "quota_contexts",
    "schema_version",
}
REAL_DISCOVERY_DESTINATIONS = (
    "brave_search_api",
    "tavily_search_api",
    "greenhouse_official_api",
    "lever_global_official_api",
    "lever_eu_official_api",
)
REAL_DISCOVERY_BOUNDS = (
    ("MAX_DISCOVERY_QUERIES", MAX_DISCOVERY_QUERIES),
    ("MAX_DISCOVERY_PHRASES", MAX_DISCOVERY_PHRASES),
    ("MAX_APPROVED_PHRASE_CHARS", MAX_APPROVED_PHRASE_CHARS),
    ("MAX_DISCOVERY_QUERY_CHARS", MAX_DISCOVERY_QUERY_CHARS),
    ("MAX_DISCOVERY_RESULTS_PER_QUERY", MAX_DISCOVERY_RESULTS_PER_QUERY),
    ("MAX_BRAVE_REQUESTS_PER_RUN", MAX_BRAVE_REQUESTS_PER_RUN),
    ("MAX_TAVILY_REQUESTS_PER_RUN", MAX_TAVILY_REQUESTS_PER_RUN),
    ("MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN", MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN),
    ("MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN", MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN),
    ("MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN", MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN),
)


class GateCRecoveryError(ValueError):
    """Stable, sanitized recovery failure."""

    def __init__(self, code: str) -> None:
        self.code = code if code.startswith("gate_c_recovery_") else "gate_c_recovery_failed"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class RecoveryTrustAnchor:
    """Operator-supplied identity anchor for one historical recovery."""

    operation_id: str
    profile_id: str
    profile_version: int
    profile_sha256: str
    policy_sha256: str
    plan_sha256: str
    report_sha256: str
    state: str
    terminal_code: str
    source_keys: tuple[str, ...]
    search_request_identities: tuple[str, ...]
    official_request_identities: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GateCRecoveryResult:
    operation_id: str
    state: str
    terminal_code: str
    plan_sha256: str
    report_sha256: str
    source_plan_sha256: str
    verified_source_count: int
    evidence_path: Path
    manifest_path: Path
    verdict_path: Path

    def as_dict(self) -> dict[str, object]:
        return {
            "result": "recovered",
            "gate": "C",
            "mode": "offline-recovery",
            "downstream": "disabled",
            "operation_id": self.operation_id,
            "state": self.state,
            "terminal_code": self.terminal_code,
            "plan_sha256": self.plan_sha256,
            "report_sha256": self.report_sha256,
            "source_plan_sha256": self.source_plan_sha256,
            "verified_source_count": self.verified_source_count,
            "evidence_path": str(self.evidence_path),
            "manifest_path": str(self.manifest_path),
            "verdict_path": str(self.verdict_path),
        }


def _fail(code: str) -> GateCRecoveryError:
    return GateCRecoveryError(code)


def _parse_utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _fail(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _fail(code) from exc
    if parsed.tzinfo is not UTC:
        raise _fail(code)
    return parsed


def _plain_path(path: Path) -> bool:
    return path.is_absolute() and not any(part in {"", ".", ".."} for part in path.parts)


def _resolved_path(path: Path, *, strict: bool) -> Path:
    if not _plain_path(path):
        raise _fail("gate_c_recovery_artifact_path_invalid")
    try:
        resolved = path.resolve(strict=strict)
    except OSError as exc:
        raise _fail("gate_c_recovery_artifact_unreadable") from exc
    if resolved != path:
        raise _fail("gate_c_recovery_artifact_path_invalid")
    return resolved


def _read_json(path: Path, *, root: Path) -> dict[str, Any]:
    if not _plain_path(path) or path.is_symlink() or path.parent == path:
        raise _fail("gate_c_recovery_artifact_path_invalid")
    try:
        resolved_root = _resolved_path(root, strict=True)
        resolved_path = _resolved_path(path, strict=True)
        relative = resolved_path.relative_to(resolved_root)
        metadata = path.lstat()
    except (OSError, ValueError) as exc:
        raise _fail("gate_c_recovery_artifact_unreadable") from exc
    if not relative.parts or not stat.S_ISREG(metadata.st_mode):
        raise _fail("gate_c_recovery_artifact_path_invalid")
    current = path.parent
    while current != root:
        try:
            directory = current.lstat()
        except OSError as exc:
            raise _fail("gate_c_recovery_artifact_unreadable") from exc
        if (
            not stat.S_ISDIR(directory.st_mode)
            or stat.S_ISLNK(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise _fail("gate_c_recovery_artifact_permissions_invalid")
        current = current.parent
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise _fail("gate_c_recovery_artifact_permissions_invalid")
    max_bytes = {
        "operation-v1.json": MAX_OPERATION_ARTIFACT_BYTES,
        "started-v1.json": MAX_START_MARKER_BYTES,
        "terminal-report-v1.json": MAX_TERMINAL_REPORT_BYTES,
    }.get(path.name, MAX_RECOVERY_ARTIFACT_BYTES)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            raw = os.read(descriptor, max_bytes + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            not 0 < len(raw) <= max_bytes
            or before.st_size != after.st_size
            or before.st_ino != after.st_ino
            or before.st_dev != after.st_dev
        ):
            raise _fail("gate_c_recovery_artifact_unreadable")
        value = loads_bounded_artifact(raw, max_bytes=max_bytes)
    except GateCRecoveryError:
        raise
    except (OSError, DiscoveryArtifactError) as exc:
        raise _fail("gate_c_recovery_artifact_invalid") from exc
    return dict(value)


def _validate_root(root: Path, *, create: bool) -> None:
    if not _plain_path(root) or root.is_symlink():
        raise _fail("gate_c_recovery_root_invalid")
    if not root.exists():
        if not create:
            raise _fail("gate_c_recovery_root_invalid")
        try:
            root.mkdir(mode=0o700, parents=False)
        except OSError as exc:
            raise _fail("gate_c_recovery_root_invalid") from exc
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise _fail("gate_c_recovery_root_invalid") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise _fail("gate_c_recovery_root_invalid")
    _resolved_path(root, strict=True)


def _write_idempotent(path: Path, payload: bytes) -> None:
    """Write once; an exact repeat is harmless, a conflict is not."""

    if len(payload) > MAX_RECOVERY_OUTPUT_BYTES:
        raise _fail("gate_c_recovery_output_too_large")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    except OSError as exc:
        raise _fail("gate_c_recovery_output_conflict") from exc
    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode):
            raise _fail("gate_c_recovery_output_conflict") from None
        try:
            if metadata.st_size > MAX_RECOVERY_OUTPUT_BYTES:
                raise _fail("gate_c_recovery_output_conflict")
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            try:
                before = os.fstat(fd)
                existing = os.read(fd, MAX_RECOVERY_OUTPUT_BYTES + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise _fail("gate_c_recovery_output_conflict") from exc
        if (
            before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_ino != after.st_ino
            or before.st_dev != after.st_dev
            or len(existing) > MAX_RECOVERY_OUTPUT_BYTES
            or existing != payload
        ):
            raise _fail("gate_c_recovery_output_conflict") from None
        return
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".recovery-", dir=path.parent)
        temporary = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            try:
                winner = path.lstat()
                if (
                    stat.S_ISREG(winner.st_mode)
                    and winner.st_uid == os.geteuid()
                    and stat.S_IMODE(winner.st_mode) == 0o600
                ):
                    winner_fd = os.open(
                        path,
                        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    )
                    try:
                        existing = os.read(winner_fd, MAX_RECOVERY_OUTPUT_BYTES + 1)
                    finally:
                        os.close(winner_fd)
                    if existing == payload:
                        return
            except OSError as exc:
                raise _fail("gate_c_recovery_output_conflict") from exc
            raise _fail("gate_c_recovery_output_conflict") from None
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise _fail("gate_c_recovery_output_failed") from exc
    finally:
        if temporary is not None:
            with suppress(FileNotFoundError):
                temporary.unlink()


def _packet(
    value: Mapping[str, Any], historical_root: Path
) -> tuple[AcceptedGateBBinding, Mapping[str, Any]]:
    if set(value) != _PACKET_KEYS:
        raise _fail("gate_c_recovery_packet_invalid")
    raw_packet = value.get("gate_b_packet")
    auth = value.get("authorization")
    if not isinstance(raw_packet, Mapping) or not isinstance(auth, Mapping):
        raise _fail("gate_c_recovery_packet_invalid")
    if set(raw_packet) != GATE_B_PACKET_KEYS:
        raise _fail("gate_c_recovery_packet_invalid")
    try:
        packet_values = dict(raw_packet)
        if packet_values.pop("schema_version", None) != GATE_B_SCHEMA_VERSION:
            raise _fail("gate_c_recovery_packet_invalid")
        packet = GateBPacket(**packet_values)
    except Exception as exc:
        raise _fail("gate_c_recovery_packet_invalid") from exc
    if gate_b_packet_sha256(packet) != value.get("gate_b_packet_sha256"):
        raise _fail("gate_c_recovery_packet_hash_invalid")
    if dict(raw_packet) != packet.payload():
        raise _fail("gate_c_recovery_packet_invalid")
    if packet.root != str(historical_root):
        raise _fail("gate_c_recovery_root_mismatch")
    if set(auth) != _AUTH_KEYS:
        raise _fail("gate_c_recovery_authorization_invalid")
    provenance = auth.get("provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != _PROVENANCE_KEYS:
        raise _fail("gate_c_recovery_authorization_invalid")
    try:
        parsed_provenance = GateCProvenance(**dict(provenance))
    except Exception as exc:
        raise _fail("gate_c_recovery_authorization_invalid") from exc
    if (
        auth.get("schema_version") != "f10.1f-gate-c-authorization-v1"
        or auth.get("gate") != "C"
        or auth.get("mode") != "report-only"
        or auth.get("report_only") is not True
        or auth.get("artifact_class") != "offline_private_report_only"
        or parsed_provenance.approved_root != str(historical_root)
    ):
        raise _fail("gate_c_recovery_authorization_invalid")
    if parsed_provenance.gate_b_packet_sha256 != value.get("gate_b_packet_sha256"):
        raise _fail("gate_c_recovery_binding_mismatch")
    expected_auth_values = {
        "budget_units": packet.budget_units,
        "max_board_candidates": packet.corpus_count,
        "max_board_verifications": packet.holdout_count,
        "max_brave_requests": 4,
        "max_tavily_requests": 4,
        "max_wire_attempts": 100,
        "per_board_cap": packet.per_board_cap,
        "per_company_cap": packet.per_company_cap,
    }
    for name, expected in expected_auth_values.items():
        actual = auth.get(name)
        if type(actual) is not int or actual != expected:
            raise _fail("gate_c_recovery_binding_mismatch")
    try:
        if str(UUID(str(auth["operation_id"]))) != auth["operation_id"]:
            raise _fail("gate_c_recovery_authorization_invalid")
        if str(UUID(str(auth["lineage_id"]))) != auth["lineage_id"]:
            raise _fail("gate_c_recovery_authorization_invalid")
    except (TypeError, ValueError) as exc:
        raise _fail("gate_c_recovery_authorization_invalid") from exc
    if (
        packet.profile_id != parsed_provenance.profile_id
        or packet.profile_version != parsed_provenance.profile_version
        or packet.profile_sha256 != parsed_provenance.profile_sha256
        or packet.policy_id != parsed_provenance.policy_id
        or packet.policy_version != parsed_provenance.policy_version
        or packet.policy_sha256 != parsed_provenance.policy_sha256
        or packet.code_commit_sha256 != parsed_provenance.candidate_commit_sha256
        or packet.namespace != parsed_provenance.namespace
        or packet.window_start_utc != parsed_provenance.window_start_utc
        or packet.window_end_utc != parsed_provenance.window_end_utc
        or parsed_provenance.budget_units != packet.budget_units
    ):
        raise _fail("gate_c_recovery_binding_mismatch")
    try:
        expected_report = {
            "code": "gate_b_packet_ready",
            "packet_sha256": gate_b_packet_sha256(packet),
            "result": "ready",
        }
        if value.get("gate_b_report") != expected_report:
            raise _fail("gate_c_recovery_packet_invalid")
        AcceptedGateBBinding(
            packet=packet,
            packet_sha256=gate_b_packet_sha256(packet),
            report=PreflightReport(
                result="ready",
                code="gate_b_packet_ready",
                code_commit_sha256=packet.code_commit_sha256,
                profile_sha256=packet.profile_sha256,
                policy_sha256=packet.policy_sha256,
                packet_sha256=gate_b_packet_sha256(packet),
            ),
        )
    except GateCRecoveryError:
        raise
    except Exception as exc:
        raise _fail("gate_c_recovery_packet_invalid") from exc

    packet_start = _parse_utc(packet.window_start_utc, "gate_c_recovery_packet_invalid")
    packet_end = _parse_utc(packet.window_end_utc, "gate_c_recovery_packet_invalid")
    auth_expiry = _parse_utc(auth.get("expires_at_utc"), "gate_c_recovery_authorization_invalid")
    if auth_expiry != packet_end or auth_expiry != _parse_utc(
        parsed_provenance.cutoff_utc, "gate_c_recovery_authorization_invalid"
    ):
        raise _fail("gate_c_recovery_binding_mismatch")
    expected_caps = {
        "budget_units": packet.budget_units,
        "corpus_count": packet.corpus_count,
        "holdout_count": packet.holdout_count,
        "max_board_candidates": auth["max_board_candidates"],
        "max_board_verifications": auth["max_board_verifications"],
        "max_brave_requests": auth["max_brave_requests"],
        "max_tavily_requests": auth["max_tavily_requests"],
        "max_wire_attempts": auth["max_wire_attempts"],
        "per_board_cap": packet.per_board_cap,
        "per_company_cap": packet.per_company_cap,
        "pilot_count": packet.pilot_count,
    }
    if value.get("caps_budget") != expected_caps:
        raise _fail("gate_c_recovery_binding_mismatch")
    expected_quota = {
        "config_version": PACKET_QUOTA_CONFIG_VERSION,
        "paid_disabled": True,
        "utc_month": packet_start.strftime("%Y-%m"),
    }
    quota = value.get("quota")
    if (
        not isinstance(quota, Mapping)
        or set(quota) != set(expected_quota)
        or quota["paid_disabled"] is not True
    ):
        raise _fail("gate_c_recovery_binding_mismatch")
    if (
        quota["config_version"] != PACKET_QUOTA_CONFIG_VERSION
        or quota["utc_month"] != expected_quota["utc_month"]
    ):
        raise _fail("gate_c_recovery_binding_mismatch")
    auth_values = dict(auth)
    auth_values["_quota_config_version"] = quota["config_version"]
    if (
        packet.corpus_count > MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN
        or packet.holdout_count > MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN
    ):
        raise _fail("gate_c_recovery_budget_mismatch")
    if (
        auth_values["max_brave_requests"] > MAX_BRAVE_REQUESTS_PER_RUN
        or auth_values["max_tavily_requests"] > MAX_TAVILY_REQUESTS_PER_RUN
        or auth_values["max_board_verifications"] > MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN
        or auth_values["max_wire_attempts"] > MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN
    ):
        raise _fail("gate_c_recovery_budget_mismatch")
    if (
        value.get("seed_origin") != packet.seed_origin
        or value.get("plan_sha256") != parsed_provenance.query_plan_sha256
    ):
        raise _fail("gate_c_recovery_binding_mismatch")
    if value.get("derived_code_commit_sha256") != packet.code_commit_sha256:
        raise _fail("gate_c_recovery_binding_mismatch")
    git_sha = value.get("git_sha")
    if (
        not isinstance(git_sha, str)
        or len(git_sha) != 40
        or any(char not in "0123456789abcdef" for char in git_sha)
        or hashlib.sha256(git_sha.encode("ascii")).hexdigest() != packet.code_commit_sha256
        or value.get("derivation") != f'sha256hex(ascii("{git_sha}"))'
    ):
        raise _fail("gate_c_recovery_binding_mismatch")
    if type(value.get("revision")) is not int or value["revision"] < 1:
        raise _fail("gate_c_recovery_packet_invalid")
    window = value.get("window")
    if window != {
        "cutoff_utc": parsed_provenance.cutoff_utc,
        "expires_at_utc": auth["expires_at_utc"],
        "window_end_utc": packet.window_end_utc,
        "window_start_utc": packet.window_start_utc,
    }:
        raise _fail("gate_c_recovery_binding_mismatch")
    expires_iso = auth_expiry.isoformat()
    expected_claims = {
        "bounds": [list(item) for item in REAL_DISCOVERY_BOUNDS],
        "brave_units_limit": auth["max_brave_requests"],
        "budget_units": packet.budget_units,
        "destinations": list(REAL_DISCOVERY_DESTINATIONS),
        "expires_at": expires_iso,
        "lineage_id": auth["lineage_id"],
        "namespace": packet.namespace,
        "operation_id": auth["operation_id"],
        "per_board_cap": packet.per_board_cap,
        "per_company_cap": packet.per_company_cap,
        "query_plan_sha256": parsed_provenance.query_plan_sha256,
        "root": str(historical_root),
        "tavily_units_limit": auth["max_tavily_requests"],
        "ttl_seconds": int((auth_expiry - packet_start).total_seconds()),
        "window_cutoff": expires_iso,
        "window_start": packet_start.isoformat(),
    }
    if value.get("capability_claims") != expected_claims:
        raise _fail("gate_c_recovery_binding_mismatch")
    return AcceptedGateBBinding(
        packet=packet,
        packet_sha256=gate_b_packet_sha256(packet),
        report=PreflightReport(
            result="ready",
            code="gate_b_packet_ready",
            code_commit_sha256=packet.code_commit_sha256,
            profile_sha256=packet.profile_sha256,
            policy_sha256=packet.policy_sha256,
            packet_sha256=gate_b_packet_sha256(packet),
        ),
    ), auth_values


def _operation(
    value: Mapping[str, Any], packet: GateBPacket, auth: Mapping[str, Any]
) -> DiscoveryOperationV2:
    if set(value) != _OPERATION_KEYS:
        raise _fail("gate_c_recovery_operation_invalid")
    try:
        if (
            value.get("schema_version") != "report-only-operation-v1"
            or value.get("operation_kind") != "continuous_discovery_v2_report_only"
        ):
            raise _fail("gate_c_recovery_operation_invalid")
        policy = value["policy_identity"]
        plan = value["plan_identity"]
        if not isinstance(policy, Mapping) or not isinstance(plan, Mapping):
            raise _fail("gate_c_recovery_operation_invalid")
        if dict(policy) != {
            "schema_version": 1,
            "policy_version": packet.policy_version,
            "policy_sha256": packet.policy_sha256,
        } or dict(plan) != {
            "schema_version": "discovery-query-plan-v2",
            "planner_version": "discovery-planner-v2",
            "compiler_version": "profile-terms-compiler-v1",
            "plan_sha256": auth["provenance"]["query_plan_sha256"],
        }:
            raise _fail("gate_c_recovery_binding_mismatch")
        if value["providers"] != [
            {"provider": "brave", "tier": "free", "enabled": True},
            {"provider": "tavily", "tier": "free", "enabled": True},
            {"provider": "greenhouse", "tier": "official", "enabled": True},
            {"provider": "lever", "tier": "official", "enabled": True},
        ] or value["destinations"] != list(REAL_DISCOVERY_DESTINATIONS):
            raise _fail("gate_c_recovery_operation_binding_invalid")
        contexts = tuple(ProviderQuotaContextV1(**item) for item in value["quota_contexts"])
        if len(contexts) != 2 or tuple(item.provider for item in contexts) != ("brave", "tavily"):
            raise _fail("gate_c_recovery_quota_context_invalid")
        for context, provider, maximum in zip(
            contexts,
            ("brave", "tavily"),
            (auth["max_brave_requests"], auth["max_tavily_requests"]),
            strict=True,
        ):
            if (
                context.provider != provider
                or context.tier != "free"
                or context.config_version != PROVIDER_QUOTA_CONFIG_VERSION
                or context.unit_limit != maximum
                or context.operation_max_calls != maximum
                or context.reservation_units_per_call != 1
                or context.micro_usd_limit != 0
                or context.reservation_micro_usd_per_call != 0
            ):
                raise _fail("gate_c_recovery_quota_context_invalid")
        if value["budgets"] != DEFAULT_DISCOVERY_BUDGETS.as_dict():
            raise _fail("gate_c_recovery_budget_mismatch")
        expected_profile_binding = {
            "profile_id": packet.profile_id,
            "row_version": int(packet.profile_version),
            "schema_version": 1,
            "canonical_profile_sha256": packet.profile_sha256,
        }
        if (
            not isinstance(value["profile_binding"], Mapping)
            or dict(value["profile_binding"]) != expected_profile_binding
        ):
            raise _fail("gate_c_recovery_binding_mismatch")
        profile_binding = ProfileBindingV1.model_validate(dict(value["profile_binding"]))
        operation = DiscoveryOperationV2(
            operation_id=value["operation_id"],
            kind=OperationKind.REPORT_ONLY,
            created_at=_parse_utc(value["created_at_utc"], "gate_c_recovery_operation_invalid"),
            expires_at=_parse_utc(
                value["authorization_expires_at_utc"],
                "gate_c_recovery_operation_invalid",
            ),
            profile_binding=profile_binding,
            policy_version=packet.policy_version,
            policy_sha256=packet.policy_sha256,
            plan_sha256=plan["plan_sha256"],
            budgets=DEFAULT_DISCOVERY_BUDGETS,
            quota_contexts=contexts,
            challenge_nonce=value["challenge_nonce"],
            authorization_max_ttl_seconds=value["authorization_max_ttl_seconds"],
        )
        unsigned = dict(value)
        claimed_operation_sha = unsigned.pop("operation_sha256")
        if hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest() != claimed_operation_sha:
            raise _fail("gate_c_recovery_operation_hash_invalid")
        if value["operation_id"] != auth["operation_id"]:
            raise _fail("gate_c_recovery_binding_mismatch")
        if challenge_sha256(operation) != value["challenge_sha256"]:
            raise _fail("gate_c_recovery_challenge_invalid")
        if operation.operation_id != auth["operation_id"]:
            raise _fail("gate_c_recovery_binding_mismatch")
        if (
            operation.profile_binding.profile_id != packet.profile_id
            or str(operation.profile_binding.row_version) != packet.profile_version
            or operation.profile_binding.profile_sha256 != packet.profile_sha256
        ):
            raise _fail("gate_c_recovery_binding_mismatch")
        if (
            operation.created_at
            < _parse_utc(packet.window_start_utc, "gate_c_recovery_operation_invalid")
            or operation.created_at >= operation.expires_at
            or operation.expires_at
            < _parse_utc(auth["expires_at_utc"], "gate_c_recovery_operation_invalid")
            or operation.authorization_max_ttl_seconds != 86_400
            or tuple(item.utc_month for item in contexts)
            != (operation.created_at.strftime("%Y-%m"),) * 2
        ):
            raise _fail("gate_c_recovery_binding_mismatch")
        return operation
    except GateCRecoveryError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise _fail("gate_c_recovery_operation_invalid") from exc


def _source_configs(
    sources: tuple[ReportOnlyVerifiedSourceV1, ...],
    operation_sha256: str,
    requests: tuple[Any, ...],
) -> tuple[Mapping[str, object], ...]:
    if not sources or len(sources) > 8:
        raise _fail("gate_c_recovery_sources_invalid")
    output: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for source in sources:
        try:
            expected_key = canonical_source_key(source.source_type, dict(source.configuration))
            config_hash = hashlib.sha256(
                canonical_json_bytes(dict(source.configuration))
            ).hexdigest()
        except (TypeError, ValueError) as exc:
            raise _fail("gate_c_recovery_sources_invalid") from exc
        if expected_key != source.source_key or source.source_key in seen:
            raise _fail("gate_c_recovery_sources_invalid")
        if config_hash != source.configuration_sha256:
            raise _fail("gate_c_recovery_sources_invalid")
        destination = (
            "greenhouse_official_api"
            if source.source_type == "greenhouse"
            else "lever_eu_official_api"
            if source.configuration.get("region") == "eu"
            else "lever_global_official_api"
        )
        expected_identity = hashlib.sha256(
            canonical_json_bytes(
                {
                    "operation_sha256": operation_sha256,
                    "source_type": source.source_type,
                    "source_key": source.source_key,
                    "configuration_sha256": config_hash,
                    "destination": destination,
                    "board_candidate_ordinal": source.board_candidate_ordinal,
                    "wire_attempt_ordinal": 1,
                    "collector_request_ordinal": 1,
                }
            )
        ).hexdigest()
        matches = [
            request
            for request in requests
            if request.kind == "official_verification"
            and request.board_candidate_ordinal == source.board_candidate_ordinal
        ]
        if len(matches) != 1:
            raise _fail("gate_c_recovery_sources_invalid")
        request = matches[0]
        if (
            request.provider != source.source_type
            or request.destination != destination
            or source.request_identity_sha256 != expected_identity
            or request.request_identity_sha256 != expected_identity
            or request.outcome != "succeeded"
            or request.transmission != "sent"
            or request.collector_request_ordinal != 1
            or request.wire_attempt_ordinal != 1
            or request.postings_count != source.postings_count
        ):
            raise _fail("gate_c_recovery_sources_invalid")
        seen.add(source.source_key)
        output.append(
            {
                "family": source.source_type,
                "source_key": source.source_key,
                "configuration_version": 1,
                "configuration": dict(source.configuration),
            }
        )
    return tuple(output)


def _validate_terminal_requests(
    terminal: ReportOnlyTerminalReportV1,
    auth: Mapping[str, Any],
    *,
    operation_id: str | None = None,
    operation_sha256: str | None = None,
    plan_sha256: str | None = None,
    expected_search_request_identities: tuple[str, ...] | None = None,
    expected_official_request_identities: tuple[str, ...] | None = None,
) -> None:
    requests = terminal.requests
    if operation_sha256 is not None and terminal.operation_sha256 != operation_sha256:
        raise _fail("gate_c_recovery_request_invalid")
    if tuple(item.request_ordinal for item in requests) != tuple(range(1, len(requests) + 1)):
        raise _fail("gate_c_recovery_request_invalid")
    search_counts = {"brave": 0, "tavily": 0}
    search_ordinals: set[tuple[str, int]] = set()
    verification_count = 0
    wire_count = 0
    official_ordinals: set[int] = set()
    request_identities: set[str] = set()
    search_identities: list[str] = []
    official_identities: list[str] = []
    allowed_destinations = {
        "search:brave",
        "search:tavily",
        "greenhouse_official_api",
        "lever_global_official_api",
        "lever_eu_official_api",
    }
    for request in terminal.requests:
        if (
            request.result_count > MAX_DISCOVERY_RESULTS_PER_QUERY
            or request.postings_count > MAX_VERIFIED_POSTINGS
            or request.known_count > request.result_count
            or request.unknown_count != request.result_count - request.known_count
            or request.rejected_count > request.result_count
        ):
            raise _fail("gate_c_recovery_request_invalid")
        if request.request_identity_sha256 == "0" * 64:
            raise _fail("gate_c_recovery_request_invalid")
        if request.request_identity_sha256 in request_identities:
            raise _fail("gate_c_recovery_request_invalid")
        request_identities.add(request.request_identity_sha256)
        if request.destination not in allowed_destinations:
            raise _fail("gate_c_recovery_request_invalid")
        if request.kind == "search":
            if request.provider not in search_counts:
                raise _fail("gate_c_recovery_request_invalid")
            if (
                request.transmission != "sent"
                or request.outcome not in {"succeeded", "empty", "failed", "malformed"}
                or request.query_ordinal is None
                or (request.provider, request.query_ordinal) in search_ordinals
                or request.board_candidate_ordinal is not None
                or request.collector_request_ordinal is not None
                or request.wire_attempt_ordinal is not None
                or request.postings_count != 0
            ):
                raise _fail("gate_c_recovery_request_invalid")
            search_ordinals.add((request.provider, request.query_ordinal))
            search_identities.append(request.request_identity_sha256)
            if expected_search_request_identities is not None and (
                len(search_identities) > len(expected_search_request_identities)
                or (
                    request.request_identity_sha256
                    != expected_search_request_identities[len(search_identities) - 1]
                )
            ):
                raise _fail("gate_c_recovery_request_identity_invalid")
            search_counts[request.provider] += 1
            expected_destination = {
                "brave": "search:brave",
                "tavily": "search:tavily",
            }[request.provider]
            if request.destination != expected_destination:
                raise _fail("gate_c_recovery_request_invalid")
            if operation_id is not None and plan_sha256 is not None:
                operation_key = (
                    f"cdv2:{operation_id}:{plan_sha256}:"
                    f"q{request.query_ordinal:02d}:{request.provider}"
                )
                if (
                    request.operation_key_sha256
                    != hashlib.sha256(operation_key.encode("utf-8")).hexdigest()
                ):
                    raise _fail("gate_c_recovery_request_invalid")
        else:
            verification_count += 1
            if (
                request.transmission != "sent"
                or request.outcome not in {"succeeded", "failed"}
                or request.board_candidate_ordinal is None
                or request.collector_request_ordinal != 1
                or request.wire_attempt_ordinal != 1
                or request.board_candidate_ordinal in official_ordinals
                or request.query_ordinal is not None
                or request.result_count != 0
                or request.known_count != 0
                or request.unknown_count != 0
                or request.rejected_count != 0
            ):
                raise _fail("gate_c_recovery_request_invalid")
            official_ordinals.add(request.board_candidate_ordinal)
            official_identities.append(request.request_identity_sha256)
            if expected_official_request_identities is not None and (
                len(official_identities) > len(expected_official_request_identities)
                or (
                    request.request_identity_sha256
                    != expected_official_request_identities[len(official_identities) - 1]
                )
            ):
                raise _fail("gate_c_recovery_request_identity_invalid")
            wire_count += 1
            if request.provider == "greenhouse":
                expected = "greenhouse_official_api"
            elif request.provider == "lever":
                expected = (
                    "lever_eu_official_api"
                    if request.destination == "lever_eu_official_api"
                    else "lever_global_official_api"
                )
            else:
                raise _fail("gate_c_recovery_request_invalid")
            if request.destination != expected:
                raise _fail("gate_c_recovery_request_invalid")
            if (
                operation_id is not None
                and operation_sha256 is not None
                and plan_sha256 is not None
            ):
                wire_key = (
                    f"cdv2:{operation_id}:{plan_sha256}:"
                    f"b{request.board_candidate_ordinal:02d}:w001:{request.provider}"
                )
                if (
                    request.operation_key_sha256
                    != hashlib.sha256(wire_key.encode("utf-8")).hexdigest()
                ):
                    raise _fail("gate_c_recovery_request_invalid")
    if (
        search_counts["brave"] > auth["max_brave_requests"]
        or search_counts["tavily"] > auth["max_tavily_requests"]
        or verification_count > auth["max_board_verifications"]
        or wire_count > auth["max_wire_attempts"]
    ):
        raise _fail("gate_c_recovery_budget_mismatch")
    counts = terminal.counts
    if (
        counts["search_requests_attempted"] > MAX_DISCOVERY_QUERIES * 2
        or counts["search_requests_completed"]
        > MAX_DISCOVERY_QUERIES * 2 + MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN
        or counts["classified_hits"] > MAX_DISCOVERY_QUERIES * MAX_DISCOVERY_RESULTS_PER_QUERY
        or counts["unique_board_candidates_seen"] > MAX_UNIQUE_BOARD_CANDIDATES_SEEN_PER_RUN
        or counts["unique_board_candidates_retained"] > MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN
        or counts["unique_board_candidates_retained"] > counts["unique_board_candidates_seen"]
        or counts["board_verifications_attempted"] > MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN
        or counts["boards_verified"] > counts["board_verifications_attempted"]
        or counts["verification_wire_attempts_consumed"] > MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN
    ):
        raise _fail("gate_c_recovery_terminal_counts_invalid")
    expected_counts = {
        "search_requests_attempted": len(search_ordinals),
        "search_requests_completed": sum(
            request.outcome in {"succeeded", "empty", "failed", "malformed"} for request in requests
        ),
        "classified_hits": sum(request.known_count for request in requests),
        "unique_board_candidates_seen": counts["unique_board_candidates_seen"],
        "unique_board_candidates_retained": min(counts["unique_board_candidates_seen"], 10),
        "board_verifications_attempted": verification_count,
        "boards_verified": len(terminal.verified_sources),
        "verification_wire_attempts_consumed": wire_count,
    }
    if counts != expected_counts:
        raise _fail("gate_c_recovery_terminal_counts_invalid")
    if tuple(search_identities) != expected_search_request_identities:
        raise _fail("gate_c_recovery_request_identity_invalid")
    if tuple(official_identities) != expected_official_request_identities:
        raise _fail("gate_c_recovery_request_identity_invalid")


def _validate_partial_terminal(terminal: ReportOnlyTerminalReportV1) -> None:
    allowed_codes = {
        "board_verifications_exhausted": "board_verifications",
        "unique_board_candidates_exhausted": "unique_board_candidates",
        "verification_wire_attempts_exhausted": "verification_wire_attempts",
    }
    if terminal.state != "completed_partial" or not terminal.verified_sources:
        raise _fail("gate_c_recovery_state_ineligible")
    exhausted = {
        "unique_board_candidates": terminal.counts["unique_board_candidates_seen"]
        >= MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN,
        "board_verifications": terminal.counts["board_verifications_attempted"]
        >= MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN,
        "verification_wire_attempts": terminal.counts["verification_wire_attempts_consumed"]
        >= MAX_VERIFICATION_WIRE_ATTEMPTS_PER_RUN,
    }
    active_flags = {name for name, enabled in terminal.truncation.items() if enabled}
    if any(
        (terminal.truncation[name] and not exhausted[name])
        or (not terminal.truncation[name] and exhausted[name])
        for name in exhausted
    ):
        raise _fail("gate_c_recovery_state_ineligible")
    if any(
        source.board_candidate_ordinal > terminal.counts["unique_board_candidates_retained"]
        for source in terminal.verified_sources
    ):
        raise _fail("gate_c_recovery_state_ineligible")
    if terminal.terminal_code == "multiple_budgets_exhausted":
        if len(active_flags) < 2 or not all(exhausted[name] for name in active_flags):
            raise _fail("gate_c_recovery_state_ineligible")
    elif terminal.terminal_code in allowed_codes:
        expected = allowed_codes[terminal.terminal_code]
        if active_flags != {expected} or not exhausted[expected]:
            raise _fail("gate_c_recovery_state_ineligible")
    else:
        raise _fail("gate_c_recovery_state_ineligible")


def _validate_trusted_anchor(
    anchor: RecoveryTrustAnchor,
    packet: GateBPacket,
    operation: DiscoveryOperationV2,
    terminal: ReportOnlyTerminalReportV1,
) -> None:
    if (
        not isinstance(anchor, RecoveryTrustAnchor)
        or anchor.operation_id != operation.operation_id
        or anchor.profile_id != packet.profile_id
        or anchor.profile_version != int(packet.profile_version)
        or anchor.profile_sha256 != packet.profile_sha256
        or anchor.policy_sha256 != packet.policy_sha256
        or anchor.plan_sha256 != terminal.plan_sha256
        or anchor.report_sha256 != terminal.report_sha256
        or anchor.state != terminal.state
        or anchor.terminal_code != terminal.terminal_code
        or anchor.source_keys != tuple(source.source_key for source in terminal.verified_sources)
        or anchor.search_request_identities
        != tuple(
            request.request_identity_sha256
            for request in terminal.requests
            if request.kind == "search"
        )
        or anchor.official_request_identities
        != tuple(
            request.request_identity_sha256
            for request in terminal.requests
            if request.kind == "official_verification"
        )
    ):
        raise _fail("gate_c_recovery_trust_anchor_mismatch")


def _validate_recovery_window(
    packet: GateBPacket,
    auth: Mapping[str, Any],
    operation: DiscoveryOperationV2,
    terminal: ReportOnlyTerminalReportV1,
) -> None:
    packet_start = _parse_utc(packet.window_start_utc, "gate_c_recovery_window_invalid")
    packet_expiry = _parse_utc(auth["expires_at_utc"], "gate_c_recovery_window_invalid")
    if (
        terminal.started_at_utc < packet_start
        or terminal.started_at_utc < operation.created_at
        or terminal.started_at_utc >= packet_expiry
        or terminal.completed_at_utc > packet_expiry
        or terminal.completed_at_utc > operation.expires_at
        or terminal.started_at_utc >= terminal.completed_at_utc
    ):
        raise _fail("gate_c_recovery_window_invalid")


def validate_partial_gate_c_semantics(
    terminal: ReportOnlyTerminalReportV1,
    packet: GateBPacket,
    auth: Mapping[str, Any],
    operation: DiscoveryOperationV2,
    *,
    trusted_anchor: RecoveryTrustAnchor,
    operation_sha256: str,
    plan_sha256: str,
) -> None:
    """Apply the complete pure recovered Gate C semantic boundary."""

    _validate_terminal_requests(
        terminal,
        auth,
        operation_id=operation.operation_id,
        operation_sha256=operation_sha256,
        plan_sha256=plan_sha256,
        expected_search_request_identities=trusted_anchor.search_request_identities,
        expected_official_request_identities=trusted_anchor.official_request_identities,
    )
    _validate_partial_terminal(terminal)
    _validate_recovery_window(packet, auth, operation, terminal)
    _validate_trusted_anchor(trusted_anchor, packet, operation, terminal)


def _profile_binding_matches(value: object, packet: GateBPacket) -> bool:
    expected = {
        "profile_id": packet.profile_id,
        "row_version": int(packet.profile_version),
        "schema_version": 1,
        "canonical_profile_sha256": packet.profile_sha256,
    }
    return isinstance(value, Mapping) and dict(value) == expected


def _evidence_payload(result: ReportOnlyTerminalReportV1, source_plan: SourcePlan) -> bytes:
    entries = [
        {
            "family": source.source_type,
            "source_key": source.source_key,
            "configuration": dict(source.configuration),
            "configuration_sha256": source.configuration_sha256,
            "postings_count": source.postings_count,
            "board_candidate_ordinal": source.board_candidate_ordinal,
            "request_identity_sha256": source.request_identity_sha256,
        }
        for source in result.verified_sources
    ]
    return canonical_artifact_json(
        {
            "plan_sha256": result.plan_sha256,
            "report_sha256": result.report_sha256,
            "source_plan_sha256": source_plan.source_plan_sha256,
            "verified_sources": entries,
        }
    )


def recover_completed_partial(
    *,
    historical_root: Path,
    packet_path: Path,
    operation_path: Path,
    terminal_report_path: Path,
    recovery_root: Path,
    verdict_path: Path,
    approval_reference: str,
    trusted_anchor: RecoveryTrustAnchor | None = None,
) -> GateCRecoveryResult:
    """Recover verified official boards without any provider or DB activity."""

    if (
        not isinstance(approval_reference, str)
        or len(approval_reference) > MAX_APPROVAL_REFERENCE_CHARS
        or _APPROVAL_REFERENCE_RE.fullmatch(approval_reference) is None
    ):
        raise _fail("gate_c_recovery_approval_required")
    if not verdict_path.is_absolute() or verdict_path.parent != recovery_root:
        raise _fail("gate_c_recovery_verdict_path_invalid")
    _validate_root(historical_root, create=False)
    if packet_path != historical_root / "gate-c-packet.json":
        raise _fail("gate_c_recovery_artifact_path_invalid")
    packet = _read_json(packet_path, root=historical_root)
    if packet.get("approval_reference_NOT_GRANTED") != approval_reference:
        raise _fail("gate_c_recovery_approval_mismatch")
    historical_resolved = _resolved_path(historical_root, strict=True)
    recovery_candidate = (
        _resolved_path(recovery_root, strict=True)
        if recovery_root.exists()
        else _resolved_path(recovery_root.parent, strict=True) / recovery_root.name
    )
    if (
        recovery_candidate == historical_resolved
        or recovery_candidate.is_relative_to(historical_resolved)
        or historical_resolved.is_relative_to(recovery_candidate)
    ):
        raise _fail("gate_c_recovery_root_overlap")
    accepted_b, auth = _packet(packet, historical_root)
    _validate_root(recovery_root, create=True)
    gate_b = accepted_b.packet
    operation_id = auth.get("operation_id")
    operation_dir = historical_root / "report-only" / "operations" / str(operation_id)
    expected_operation_path = operation_dir / "operation-v1.json"
    expected_start_path = operation_dir / "started-v1.json"
    expected_terminal_path = operation_dir / "terminal-report-v1.json"
    if operation_path != expected_operation_path or terminal_report_path != expected_terminal_path:
        raise _fail("gate_c_recovery_artifact_path_invalid")
    operation_payload = _read_json(operation_path, root=historical_root)
    operation = _operation(operation_payload, gate_b, auth)
    try:
        start_payload = _read_json(expected_start_path, root=historical_root)
        start = parse_start_marker(start_payload)
        terminal_payload = _read_json(terminal_report_path, root=historical_root)
        terminal = parse_terminal_report(terminal_payload)
    except Exception as exc:
        if isinstance(exc, GateCRecoveryError):
            raise
        raise _fail("gate_c_recovery_report_invalid") from exc
    expected_auth_sha = hashlib.sha256(
        canonical_json_bytes(
            {
                "operation_id": operation.operation_id,
                "operation_sha256": operation_payload["operation_sha256"],
                "challenge_sha256": operation_payload["challenge_sha256"],
                "expires_at_utc": operation_payload["authorization_expires_at_utc"],
            }
        )
    ).hexdigest()
    for artifact in (start, terminal):
        if (
            artifact.operation_id != operation.operation_id
            or artifact.operation_sha256 != operation_payload["operation_sha256"]
            or artifact.challenge_sha256 != operation_payload["challenge_sha256"]
            or artifact.plan_sha256 != auth["provenance"]["query_plan_sha256"]
            or artifact.policy_sha256 != gate_b.policy_sha256
            or not _profile_binding_matches(artifact.profile_binding, gate_b)
            or artifact.authorization_expires_at_utc != operation.expires_at
            or artifact.authorization_sha256 != expected_auth_sha
            or artifact.quota_contexts != operation.quota_contexts
            or artifact.authorization_max_ttl_seconds != operation.authorization_max_ttl_seconds
        ):
            raise _fail("gate_c_recovery_binding_mismatch")
    if terminal.start_marker_sha256 != start.start_marker_sha256:
        raise _fail("gate_c_recovery_binding_mismatch")
    if start.started_at_utc != terminal.started_at_utc:
        raise _fail("gate_c_recovery_binding_mismatch")
    if trusted_anchor is None:
        raise _fail("gate_c_recovery_trust_anchor_required")
    validate_partial_gate_c_semantics(
        terminal,
        gate_b,
        auth,
        operation,
        trusted_anchor=trusted_anchor,
        operation_sha256=operation_payload["operation_sha256"],
        plan_sha256=operation_payload["plan_identity"]["plan_sha256"],
    )
    source_configs = _source_configs(
        terminal.verified_sources, operation_payload["operation_sha256"], terminal.requests
    )
    recovery_namespace = f"gate-c-recovery-{operation.operation_id[:8]}-{terminal.plan_sha256[:8]}"
    source_plan = build_source_plan(
        namespace=recovery_namespace,
        root=str(recovery_root),
        per_board_cap=int(auth["per_board_cap"]),
        per_company_cap=int(auth["per_company_cap"]),
        budget=SourcePlanBudget(str(packet["gate_b_packet_sha256"]), int(auth["budget_units"])),
        seed=SeedInputs(gate_b.selection_seed, gate_b.partition_seed),
        operation_id=operation.operation_id,
        lineage_id=f"recovery-{auth['lineage_id']}",
        source_configs=source_configs,
    )
    gate_c_dir = recovery_root / "gate-c"
    try:
        gate_c_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _fail("gate_c_recovery_output_failed") from exc
    try:
        gate_c_metadata = gate_c_dir.lstat()
    except OSError as exc:
        raise _fail("gate_c_recovery_output_failed") from exc
    if (
        not stat.S_ISDIR(gate_c_metadata.st_mode)
        or stat.S_ISLNK(gate_c_metadata.st_mode)
        or gate_c_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(gate_c_metadata.st_mode) != 0o700
    ):
        raise _fail("gate_c_recovery_output_conflict")
    evidence_dir = gate_c_dir / terminal.plan_sha256
    try:
        evidence_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _fail("gate_c_recovery_output_failed") from exc
    try:
        evidence_metadata = evidence_dir.lstat()
    except OSError as exc:
        raise _fail("gate_c_recovery_output_failed") from exc
    if (
        not stat.S_ISDIR(evidence_metadata.st_mode)
        or stat.S_ISLNK(evidence_metadata.st_mode)
        or evidence_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(evidence_metadata.st_mode) != 0o700
    ):
        raise _fail("gate_c_recovery_output_conflict")
    evidence_path = evidence_dir / "real_discovery_evidence.json"
    _write_idempotent(evidence_path, _evidence_payload(terminal, source_plan))
    manifest = {
        "schema_version": RECOVERY_MANIFEST_SCHEMA,
        "approval_reference": approval_reference,
        "operation_id": operation.operation_id,
        "operation_sha256": operation_payload["operation_sha256"],
        "report_sha256": terminal.report_sha256,
        "plan_sha256": terminal.plan_sha256,
        "source_plan_sha256": source_plan.source_plan_sha256,
        "state": terminal.state,
        "terminal_code": terminal.terminal_code,
        "verified_source_count": len(terminal.verified_sources),
        "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
    }
    manifest_path = recovery_root / "recovery-manifest.json"
    try:
        manifest_bytes = canonical_artifact_json(manifest) + b"\n"
    except DiscoveryArtifactError as exc:
        raise _fail("gate_c_recovery_output_too_large") from exc
    _write_idempotent(manifest_path, manifest_bytes)
    verdict = {
        "schema_version": RECOVERY_VERDICT_SCHEMA,
        "result": "passed",
        "operation_id": operation.operation_id,
        "operation_sha256": operation_payload["operation_sha256"],
        "report_sha256": terminal.report_sha256,
        "plan_sha256": terminal.plan_sha256,
        "source_plan_sha256": source_plan.source_plan_sha256,
        "verified_source_count": len(terminal.verified_sources),
        "checks": ["packet", "operation", "start_marker", "terminal_report", "sources", "evidence"],
        "network": "not_used",
        "credentials": "not_used",
        "quota": "not_used",
        "downstream": "disabled",
    }
    try:
        verdict_bytes = canonical_artifact_json(verdict) + b"\n"
    except DiscoveryArtifactError as exc:
        raise _fail("gate_c_recovery_output_too_large") from exc
    _write_idempotent(verdict_path, verdict_bytes)
    return GateCRecoveryResult(
        operation_id=operation.operation_id,
        state=terminal.state,
        terminal_code=terminal.terminal_code or "",
        plan_sha256=terminal.plan_sha256,
        report_sha256=terminal.report_sha256,
        source_plan_sha256=source_plan.source_plan_sha256,
        verified_source_count=len(terminal.verified_sources),
        evidence_path=evidence_path,
        manifest_path=manifest_path,
        verdict_path=verdict_path,
    )


__all__ = [
    "GateCRecoveryError",
    "GateCRecoveryResult",
    "RecoveryTrustAnchor",
    "recover_completed_partial",
    "validate_partial_gate_c_semantics",
]
