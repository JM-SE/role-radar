"""Controlled composition root for one real R2 Gate C operation.

The lower-level Gate C modules deliberately expose dependency seams instead of
opening production resources themselves.  This module is the named operator
boundary that joins those seams in one direction only:

``packet -> independent verification -> credentials/providers -> report-only``

It never invokes Post-C, Gate D, Gate E, or Gate F, and it never writes normal
Source/Job rows.  Quota reservations and report-only evidence are the only
durable effects available through the supplied repository/artifact seams.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import stat
import subprocess
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from sqlalchemy.orm import Session

from role_radar.acquisition.credentials import CredentialResolver
from role_radar.continuous_acquisition.runtime_discovery_v2 import build_discovery_plan
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    PreflightReport,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
    gate_b_packet_sha256,
    parse_gate_c_authorization,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import (
    GateCResult,
    execute_gate_c_real_discovery,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_capability import (
    REAL_DISCOVERY_BOUNDS,
    REAL_DISCOVERY_DESTINATIONS,
    ApprovedRealDiscoveryCapability,
    capability_from_independent_verifier,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_verifier import (
    IndependentPacketVerifier,
)
from role_radar.evaluation.profile_relevant_acquisition.real_gate_c_discovery import (
    run_real_gate_c_discovery,
)
from role_radar.repositories.acquisition import AcquisitionRepository

MAX_PACKET_BYTES = 128 * 1024
DEFAULT_LIVE_TTL_SECONDS = 90 * 60


class RealGateCOperationError(ValueError):
    """Sanitized failure from the controlled live Gate C boundary."""

    def __init__(self, code: str) -> None:
        self.code = code if code.startswith("r2_gate_c_") else "r2_gate_c_failed"
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class RealGateCExecution:
    """Public operation result; packet and evidence paths contain no secrets."""

    result: GateCResult
    packet_path: Path
    verdict_path: Path
    evidence_root: Path

    def as_dict(self) -> dict[str, object]:
        return {
            "result": "completed",
            "gate": "C",
            "mode": "report-only",
            "downstream": "disabled",
            "packet_path": str(self.packet_path),
            "verdict_path": str(self.verdict_path),
            "evidence_root": str(self.evidence_root),
            **self.result.public.as_dict(),
        }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RealGateCOperationError("r2_gate_c_packet_unreadable") from exc
    if not 0 < len(raw) <= MAX_PACKET_BYTES:
        raise RealGateCOperationError("r2_gate_c_packet_unreadable")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RealGateCOperationError("r2_gate_c_packet_invalid") from exc
    if not isinstance(value, dict):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    return value


def _packet_components(document: Mapping[str, Any]) -> tuple[GateBPacket, GateCAuthorization]:
    section = document.get("gate_b_packet")
    authorization = document.get("authorization")
    if not isinstance(section, Mapping) or not isinstance(authorization, Mapping):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    values = dict(section)
    values.pop("schema_version", None)
    try:
        packet = GateBPacket(**values)
        auth = parse_gate_c_authorization(authorization)
    except Exception as exc:
        raise RealGateCOperationError("r2_gate_c_packet_invalid") from exc
    return packet, auth


def _accepted_gate_b(packet: GateBPacket) -> AcceptedGateBBinding:
    packet_hash = gate_b_packet_sha256(packet)
    return AcceptedGateBBinding(
        packet=packet,
        packet_sha256=packet_hash,
        report=PreflightReport(
            result="ready",
            code="gate_b_packet_ready",
            code_commit_sha256=packet.code_commit_sha256,
            profile_sha256=packet.profile_sha256,
            policy_sha256=packet.policy_sha256,
            packet_sha256=packet_hash,
        ),
    )


def _git_head(repo_path: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RealGateCOperationError("r2_gate_c_commit_unavailable") from exc
    head = completed.stdout.strip()
    if (
        completed.returncode != 0
        or len(head) < 40
        or any(c not in "0123456789abcdef" for c in head)
    ):
        raise RealGateCOperationError("r2_gate_c_commit_unavailable")
    return head


def _validate_private_root(root: Path) -> None:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise RealGateCOperationError("r2_gate_c_root_invalid") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or root.is_symlink()
    ):
        raise RealGateCOperationError("r2_gate_c_root_invalid")


def _validate_private_child(path: Path, root: Path, *, allow_existing: bool) -> None:
    _validate_private_root(root)
    if path.parent != root or path.is_symlink():
        raise RealGateCOperationError("r2_gate_c_artifact_path_invalid")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_existing:
            raise RealGateCOperationError("r2_gate_c_artifact_path_invalid") from None
        return
    except OSError as exc:
        raise RealGateCOperationError("r2_gate_c_artifact_path_invalid") from exc
    if (
        not allow_existing
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RealGateCOperationError("r2_gate_c_artifact_path_invalid")


def _write_private_atomic(path: Path, payload: bytes) -> None:
    _validate_private_child(path, path.parent, allow_existing=False)
    fd, temporary_name = tempfile.mkstemp(prefix=".gate-c-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise RealGateCOperationError("r2_gate_c_artifact_conflict") from exc
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except RealGateCOperationError:
        raise
    except OSError as exc:
        raise RealGateCOperationError("r2_gate_c_artifact_write_failed") from exc
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _fresh_operation_id() -> str:
    return str(uuid4())


def prepare_live_packet(
    *,
    template_path: Path,
    output_path: Path,
    evidence_root: Path,
    approval_reference: str,
    repo_path: Path,
    now: datetime | None = None,
    ttl_seconds: int = DEFAULT_LIVE_TTL_SECONDS,
) -> dict[str, object]:
    """Create a short-lived packet from an approved packet shape.

    Static profile/policy/query-plan identities and Gate B cardinalities are
    copied from the approved template; operation identity, seeds, root, window,
    and current code binding are regenerated.  This avoids silently inventing
    profile or policy values at the operator boundary.
    """

    if not approval_reference or not isinstance(approval_reference, str):
        raise RealGateCOperationError("r2_gate_c_approval_required")
    if type(ttl_seconds) is not int or not 0 < ttl_seconds <= 86_400:
        raise RealGateCOperationError("r2_gate_c_ttl_invalid")
    if now is None:
        now = datetime.now(UTC).replace(microsecond=0)
    if now.tzinfo is None or now.utcoffset() is None:
        raise RealGateCOperationError("r2_gate_c_clock_invalid")
    now = now.astimezone(UTC).replace(microsecond=0)
    expires = now + timedelta(seconds=ttl_seconds)
    if expires.month != now.month:
        raise RealGateCOperationError("r2_gate_c_month_boundary")
    if not isinstance(evidence_root, Path) or not evidence_root.is_absolute():
        raise RealGateCOperationError("r2_gate_c_root_invalid")
    _validate_private_root(evidence_root)
    document = _read_json(template_path)
    template_section = document.get("authorization")
    if not isinstance(template_section, Mapping):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    template_packet_values = document.get("gate_b_packet")
    if not isinstance(template_packet_values, Mapping):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    template_packet_values = dict(template_packet_values)
    template_packet_values.pop("schema_version", None)
    try:
        template_packet = GateBPacket(**cast(dict[str, Any], template_packet_values))
    except Exception as exc:
        raise RealGateCOperationError("r2_gate_c_packet_invalid") from exc
    # The template may be expired; its authorization is used only as a source
    # of bounded caps and is intentionally not trusted for execution.
    template_auth_values = dict(template_section)
    template_provenance = template_auth_values.get("provenance")
    if not isinstance(template_provenance, Mapping):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    head = _git_head(repo_path)
    commit_binding = sha256(head.encode("ascii")).hexdigest()
    operation_id = _fresh_operation_id()
    lineage_id = _fresh_operation_id()
    namespace = f"r2-discover-{now.strftime('%Y%m%d-%H%M%S')}-{operation_id[:8]}"
    selection_seed = secrets.token_hex(32)
    partition_seed = secrets.token_hex(32)
    window_start = _iso(now)
    window_end = _iso(expires)
    cutoff = _iso(expires)

    gate_b = template_packet.payload()
    gate_b.update(
        {
            "code_commit_sha256": commit_binding,
            "namespace": namespace,
            "root": str(evidence_root),
            "selection_seed": selection_seed,
            "partition_seed": partition_seed,
            "window_start_utc": window_start,
            "window_end_utc": window_end,
        }
    )
    gate_b_packet = GateBPacket(
        **cast(
            dict[str, Any],
            {key: value for key, value in gate_b.items() if key != "schema_version"},
        )
    )
    gate_b_hash = gate_b_packet_sha256(gate_b_packet)
    auth_doc = {
        "schema_version": "f10.1f-gate-c-authorization-v1",
        "artifact_class": template_auth_values["artifact_class"],
        "budget_units": int(template_auth_values["budget_units"]),
        "expires_at_utc": _iso(expires),
        "gate": "C",
        "lineage_id": lineage_id,
        "max_board_candidates": int(template_auth_values["max_board_candidates"]),
        "max_board_verifications": int(template_auth_values["max_board_verifications"]),
        "max_brave_requests": int(template_auth_values["max_brave_requests"]),
        "max_tavily_requests": int(template_auth_values["max_tavily_requests"]),
        "max_wire_attempts": int(template_auth_values["max_wire_attempts"]),
        "mode": "report-only",
        "operation_id": operation_id,
        "per_board_cap": int(template_auth_values["per_board_cap"]),
        "per_company_cap": int(template_auth_values["per_company_cap"]),
        "provenance": {
            "gate_b_packet_sha256": gate_b_hash,
            "candidate_commit_sha256": commit_binding,
            "profile_id": gate_b_packet.profile_id,
            "profile_version": gate_b_packet.profile_version,
            "profile_sha256": gate_b_packet.profile_sha256,
            "policy_id": gate_b_packet.policy_id,
            "policy_version": gate_b_packet.policy_version,
            "policy_sha256": gate_b_packet.policy_sha256,
            "query_plan_sha256": document.get(
                "plan_sha256", template_provenance["query_plan_sha256"]
            ),
            "namespace": namespace,
            "approved_root": str(evidence_root),
            "window_start_utc": window_start,
            "window_end_utc": window_end,
            "cutoff_utc": cutoff,
            "budget_units": gate_b_packet.budget_units,
        },
        "report_only": True,
    }
    claims = {
        "bounds": [list(item) for item in REAL_DISCOVERY_BOUNDS],
        "brave_units_limit": int(template_auth_values["max_brave_requests"]),
        "budget_units": gate_b_packet.budget_units,
        "destinations": list(REAL_DISCOVERY_DESTINATIONS),
        "expires_at": expires.isoformat(),
        "lineage_id": lineage_id,
        "namespace": namespace,
        "operation_id": operation_id,
        "per_board_cap": gate_b_packet.per_board_cap,
        "per_company_cap": gate_b_packet.per_company_cap,
        "query_plan_sha256": auth_doc["provenance"]["query_plan_sha256"],
        "root": str(evidence_root),
        "tavily_units_limit": int(template_auth_values["max_tavily_requests"]),
        "ttl_seconds": ttl_seconds,
        "window_cutoff": expires.isoformat(),
        "window_start": now.isoformat(),
    }
    template_caps = document.get("caps_budget")
    if not isinstance(template_caps, Mapping):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    quota = document.get("quota")
    if not isinstance(quota, Mapping) or not isinstance(quota.get("config_version"), str):
        raise RealGateCOperationError("r2_gate_c_packet_invalid")
    output = {
        "approval_reference_NOT_GRANTED": approval_reference,
        "authorization": auth_doc,
        "capability_claims": claims,
        "caps_budget": {
            "budget_units": gate_b_packet.budget_units,
            "corpus_count": gate_b_packet.corpus_count,
            "holdout_count": gate_b_packet.holdout_count,
            "max_board_candidates": int(template_auth_values["max_board_candidates"]),
            "max_board_verifications": int(template_auth_values["max_board_verifications"]),
            "max_brave_requests": int(template_auth_values["max_brave_requests"]),
            "max_tavily_requests": int(template_auth_values["max_tavily_requests"]),
            "max_wire_attempts": int(template_auth_values["max_wire_attempts"]),
            "per_board_cap": gate_b_packet.per_board_cap,
            "per_company_cap": gate_b_packet.per_company_cap,
            "pilot_count": gate_b_packet.pilot_count,
        },
        "derivation": f'sha256hex(ascii("{head}"))',
        "derived_code_commit_sha256": commit_binding,
        "gate_b_packet": gate_b_packet.payload(),
        "gate_b_packet_sha256": gate_b_hash,
        "gate_b_report": {
            "code": "gate_b_packet_ready",
            "packet_sha256": gate_b_hash,
            "result": "ready",
        },
        "git_sha": head,
        "plan_sha256": auth_doc["provenance"]["query_plan_sha256"],
        "quota": {
            "config_version": quota["config_version"],
            "paid_disabled": True,
            "utc_month": now.strftime("%Y-%m"),
        },
        "revision": int(document.get("revision", 0)) + 1,
        "seed_origin": "operator_supplied",
        "window": {
            "cutoff_utc": cutoff,
            "expires_at_utc": _iso(expires),
            "window_end_utc": window_end,
            "window_start_utc": window_start,
        },
    }
    _validate_private_child(output_path, evidence_root, allow_existing=False)
    payload = json.dumps(output, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_PACKET_BYTES:
        raise RealGateCOperationError("r2_gate_c_packet_too_large")
    _write_private_atomic(output_path, payload)
    _read_json(output_path)
    return {
        "result": "prepared",
        "gate": "C",
        "mode": "report-only",
        "packet_path": str(output_path),
        "evidence_root": str(evidence_root),
        "operation_id": operation_id,
        "expires_at_utc": _iso(expires),
        "gate_b_packet_sha256": gate_b_hash,
        "downstream": "disabled",
    }


def run_live_gate_c(
    *,
    packet_path: Path,
    repo_path: Path,
    history_roots: tuple[Path, ...],
    verdict_path: Path,
    approval_reference: str,
    config: object,
    plan: DiscoveryQueryPlanV2,
    session: Session,
) -> RealGateCExecution:
    """Verify and execute exactly one real Gate C report-only operation."""

    document = _read_json(packet_path)
    packet, authorization = _packet_components(document)
    if document.get("approval_reference_NOT_GRANTED") != approval_reference:
        raise RealGateCOperationError("r2_gate_c_approval_invalid")
    accepted_b = _accepted_gate_b(packet)
    evidence_root = Path(authorization.provenance.approved_root)
    if not evidence_root.is_absolute():
        raise RealGateCOperationError("r2_gate_c_root_invalid")
    _validate_private_child(packet_path, evidence_root, allow_existing=True)
    _validate_private_child(verdict_path, evidence_root, allow_existing=False)
    if not history_roots or packet_path.parent not in history_roots:
        raise RealGateCOperationError("r2_gate_c_history_scope_required")
    try:
        verifier = IndependentPacketVerifier(
            packet_path=packet_path,
            repo_path=repo_path,
            expected_approval_reference=approval_reference,
            history_roots=history_roots,
            verdict_path=verdict_path,
        )
        capability: ApprovedRealDiscoveryCapability = capability_from_independent_verifier(
            authorization,
            accepted_b,
            plan,
            config,
            verifier,
            now=datetime.now(UTC),
        )
    except Exception as exc:
        raise RealGateCOperationError("r2_gate_c_verification_failed") from exc

    resolver = cast(Any, CredentialResolver())
    quota_adapter = cast(Any, AcquisitionRepository(session))

    async def discover() -> Any:
        return await run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted_b,
            plan=plan,
            config=config,
            resolver=resolver,
            quota_adapter=quota_adapter,
            artifact_root=evidence_root,
        )

    try:
        result = asyncio.run(
            execute_gate_c_real_discovery(
                authorization=authorization,
                accepted_b=accepted_b,
                plan=plan,
                config=config,
                capability=capability,
                discover=discover,
                evidence_root=evidence_root,
            )
        )
    except Exception as exc:
        raise RealGateCOperationError("r2_gate_c_execution_failed") from exc
    return RealGateCExecution(result, packet_path, verdict_path, evidence_root)


def open_runtime_inputs(
    *, database_url: str, policy_path: Path, acquisition_config_path: Path
) -> tuple[Any, Any, Any, Any]:
    """Load the explicit policy/config and open the caller-owned DB session."""

    from role_radar.acquisition.configuration import (
        ProductionAcquisitionFilePolicy,
        load_acquisition_config,
    )
    from role_radar.acquisition.discovery_policy import (
        load_discovery_policy,
        production_discovery_policy_file_policy,
    )

    try:
        policy = load_discovery_policy(
            policy_path,
            file_policy=production_discovery_policy_file_policy(),
        )
        config = load_acquisition_config(
            acquisition_config_path,
            policy=ProductionAcquisitionFilePolicy(),
        )
        engine = get_engine(database_url)
        session = get_session_factory(engine)()
        plan = build_discovery_plan(policy=policy, session=session)
    except Exception as exc:
        raise RealGateCOperationError("r2_gate_c_runtime_inputs_invalid") from exc
    return engine, session, config, plan


__all__ = [
    "DEFAULT_LIVE_TTL_SECONDS",
    "RealGateCExecution",
    "RealGateCOperationError",
    "open_runtime_inputs",
    "prepare_live_packet",
    "run_live_gate_c",
]
