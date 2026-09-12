"""Complete, offline reconstruction boundary for recovered Gate C Post-C."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    MAX_START_MARKER_BYTES,
    MAX_TERMINAL_REPORT_BYTES,
    ReportOnlyTerminalReportV1,
    parse_start_marker,
    parse_terminal_report,
)
from role_radar.discovery.authorization_v2 import canonical_json_bytes
from role_radar.evaluation.profile_relevant_acquisition.gate_c_recovery import (
    RECOVERY_MANIFEST_SCHEMA,
    RECOVERY_VERDICT_SCHEMA,
    RecoveryTrustAnchor,
    _evidence_payload,
    _operation,
    _packet,
    _profile_binding_matches,
    _source_configs,
    validate_partial_gate_c_semantics,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_authorization import (
    HISTORICAL_PACKET_SHA256,
    RECOVERY_MANIFEST_SHA256,
    RECOVERY_VERDICT_SHA256,
    PostCAuthorization,
    PostCRecoveryAuthorizationError,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_recovery_filesystem import (
    RecoveryFilesystemError,
    pinned_root,
    read_json,
)
from role_radar.evaluation.profile_relevant_acquisition.seed_inputs import SeedInputs
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    SourcePlan,
    SourcePlanBudget,
    build_source_plan,
)


class PostCRecoveryLoadError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveredGateCPublicResult:
    operation_id: str
    plan_sha256: str
    source_plan_sha256: str
    report_sha256: str
    query_count: int
    host_count: int
    family_counts: dict[str, int]
    budget_status: str
    result: str
    reason: str | None


@dataclass(frozen=True, slots=True)
class RecoveredGateCResult:
    public: RecoveredGateCPublicResult
    source_plan: SourcePlan
    report: ReportOnlyTerminalReportV1


@dataclass(frozen=True, slots=True)
class RecoveredPostCData:
    """Loader-owned reconstruction, consumed immediately by the service."""

    authorization: PostCAuthorization
    gate_c_result: RecoveredGateCResult
    terminal: ReportOnlyTerminalReportV1
    source_plan: SourcePlan
    evidence_sha256: str
    evidence_bytes: bytes


def _fail(code: str) -> PostCRecoveryLoadError:
    return PostCRecoveryLoadError(code)


def _exact(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise _fail(code)


def _anchor(auth: PostCAuthorization) -> RecoveryTrustAnchor:
    return RecoveryTrustAnchor(
        operation_id=auth.operation_id,
        profile_id=auth.profile_id,
        profile_version=auth.profile_version,
        profile_sha256=auth.profile_sha256,
        policy_sha256=auth.policy_sha256,
        plan_sha256=auth.plan_sha256,
        report_sha256=auth.report_sha256,
        state="completed_partial",
        terminal_code="multiple_budgets_exhausted",
        source_keys=auth.source_keys,
        search_request_identities=auth.search_request_identities,
        official_request_identities=auth.official_request_identities,
    )


def _load_historical(
    auth: PostCAuthorization,
    fd: int,
) -> tuple[
    dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes
]:
    root = Path(auth.historical_root)
    operation_dir = root / "report-only" / "operations" / auth.operation_id
    try:
        packet, packet_raw = read_json(
            fd,
            root,
            root / "gate-c-packet.json",
            approved_raw_sha256=HISTORICAL_PACKET_SHA256,
        )
        operation, operation_raw = read_json(fd, root, operation_dir / "operation-v1.json")
        start, start_raw = read_json(
            fd, root, operation_dir / "started-v1.json", maximum=MAX_START_MARKER_BYTES
        )
        terminal, terminal_raw = read_json(
            fd,
            root,
            operation_dir / "terminal-report-v1.json",
            maximum=MAX_TERMINAL_REPORT_BYTES,
        )
    except RecoveryFilesystemError as exc:
        raise _fail(exc.code) from exc
    return packet, packet_raw, operation, operation_raw, start, start_raw, terminal, terminal_raw


def _load_recovery(
    auth: PostCAuthorization,
    fd: int,
) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes, dict[str, Any], bytes]:
    root = Path(auth.recovery_root)
    evidence_path = root / "gate-c" / auth.plan_sha256 / "real_discovery_evidence.json"
    try:
        manifest, manifest_raw = read_json(
            fd,
            root,
            root / "recovery-manifest.json",
            approved_raw_sha256=RECOVERY_MANIFEST_SHA256,
        )
        verdict, verdict_raw = read_json(
            fd,
            root,
            root / "recovery-verdict.json",
            approved_raw_sha256=RECOVERY_VERDICT_SHA256,
        )
        evidence, evidence_raw = read_json(fd, root, evidence_path)
    except RecoveryFilesystemError as exc:
        raise _fail(exc.code) from exc
    return manifest, manifest_raw, verdict, verdict_raw, evidence, evidence_raw


def _load_recovered_post_c_pinned(
    authorization: PostCAuthorization,
    historical_fd: int,
    recovery_fd: int,
    *,
    now: datetime,
) -> RecoveredPostCData:
    """Load and fully validate one recovered result without any effect."""

    try:
        authorization.validate_recovered_anchors()
        authorization.validate_current(now or datetime.now(UTC))
    except (PostCRecoveryAuthorizationError, RecoveryFilesystemError) as exc:
        raise _fail(getattr(exc, "code", "post_c_recovery_authorization_invalid")) from exc

    manifest, _, verdict, _, evidence, evidence_raw = _load_recovery(authorization, recovery_fd)
    if set(manifest) != {
        "schema_version",
        "approval_reference",
        "operation_id",
        "operation_sha256",
        "report_sha256",
        "plan_sha256",
        "source_plan_sha256",
        "state",
        "terminal_code",
        "verified_source_count",
        "evidence_sha256",
    } or set(verdict) != {
        "schema_version",
        "result",
        "operation_id",
        "operation_sha256",
        "report_sha256",
        "plan_sha256",
        "source_plan_sha256",
        "verified_source_count",
        "checks",
        "network",
        "credentials",
        "quota",
        "downstream",
    }:
        raise _fail("post_c_recovery_artifact_schema_invalid")
    expected_checks = [
        "packet",
        "operation",
        "start_marker",
        "terminal_report",
        "sources",
        "evidence",
    ]
    checks = (
        manifest["schema_version"] == RECOVERY_MANIFEST_SCHEMA,
        manifest["approval_reference"] == authorization.historical_approval_reference,
        manifest["operation_id"] == authorization.operation_id,
        manifest["operation_sha256"] == authorization.operation_sha256,
        manifest["report_sha256"] == authorization.report_sha256,
        manifest["plan_sha256"] == authorization.plan_sha256,
        manifest["source_plan_sha256"] == authorization.source_plan_sha256,
        manifest["state"] == "completed_partial",
        manifest["terminal_code"] == "multiple_budgets_exhausted",
        manifest["verified_source_count"] == 6,
        verdict["schema_version"] == RECOVERY_VERDICT_SCHEMA,
        verdict["result"] == "passed",
        verdict["operation_id"] == authorization.operation_id,
        verdict["operation_sha256"] == authorization.operation_sha256,
        verdict["report_sha256"] == authorization.report_sha256,
        verdict["plan_sha256"] == authorization.plan_sha256,
        verdict["source_plan_sha256"] == authorization.source_plan_sha256,
        verdict["verified_source_count"] == 6,
        verdict["checks"] == expected_checks,
        verdict["network"] == "not_used",
        verdict["credentials"] == "not_used",
        verdict["quota"] == "not_used",
        verdict["downstream"] == "disabled",
        hashlib.sha256(evidence_raw).hexdigest() == manifest["evidence_sha256"],
        manifest["evidence_sha256"] == authorization.evidence_sha256,
    )
    if not all(checks):
        raise _fail("post_c_recovery_binding_mismatch")
    if set(evidence) != {"plan_sha256", "report_sha256", "source_plan_sha256", "verified_sources"}:
        raise _fail("post_c_recovery_artifact_schema_invalid")
    if (
        evidence["plan_sha256"] != authorization.plan_sha256
        or evidence["report_sha256"] != authorization.report_sha256
        or evidence["source_plan_sha256"] != authorization.source_plan_sha256
    ):
        raise _fail("post_c_recovery_binding_mismatch")

    packet, _, operation_payload, _, _, start_raw, _, terminal_raw = _load_historical(
        authorization, historical_fd
    )
    try:
        accepted_b, packet_auth = _packet(packet, Path(authorization.historical_root))
        operation = _operation(operation_payload, accepted_b.packet, packet_auth)
        start = parse_start_marker(start_raw)
        terminal = parse_terminal_report(terminal_raw)
    except Exception as exc:
        if isinstance(exc, PostCRecoveryLoadError):
            raise
        raise _fail("post_c_recovery_historical_artifact_invalid") from exc
    historical_checks = (
        packet.get("approval_reference_NOT_GRANTED") == authorization.historical_approval_reference,
        operation_payload.get("operation_sha256") == authorization.operation_sha256,
        packet_auth.get("operation_id") == authorization.operation_id,
        packet_auth.get("provenance", {}).get("profile_id") == authorization.profile_id,
        str(packet_auth.get("provenance", {}).get("profile_version"))
        == str(authorization.profile_version),
        packet_auth.get("provenance", {}).get("profile_sha256") == authorization.profile_sha256,
        packet_auth.get("provenance", {}).get("policy_sha256") == authorization.policy_sha256,
        packet_auth.get("provenance", {}).get("query_plan_sha256") == authorization.plan_sha256,
        terminal.report_sha256 == authorization.report_sha256,
        terminal.plan_sha256 == authorization.plan_sha256,
        terminal.operation_id == authorization.operation_id,
        _profile_binding_matches(terminal.profile_binding, accepted_b.packet),
        start.operation_id == authorization.operation_id,
        start.operation_sha256 == authorization.operation_sha256,
        start.challenge_sha256 == operation_payload.get("challenge_sha256"),
        start.authorization_sha256
        == hashlib.sha256(
            canonical_json_bytes(
                {
                    "operation_id": operation.operation_id,
                    "operation_sha256": operation_payload["operation_sha256"],
                    "challenge_sha256": operation_payload["challenge_sha256"],
                    "expires_at_utc": operation_payload["authorization_expires_at_utc"],
                }
            )
        ).hexdigest(),
        start.policy_sha256 == operation_payload.get("policy_identity", {}).get("policy_sha256"),
        start.plan_sha256 == operation_payload.get("plan_identity", {}).get("plan_sha256"),
        _profile_binding_matches(start.profile_binding, accepted_b.packet),
        start.quota_contexts == operation.quota_contexts,
        start.authorization_max_ttl_seconds
        == operation_payload.get("authorization_max_ttl_seconds"),
        start.authorization_expires_at_utc == operation.expires_at,
        start.started_at_utc == terminal.started_at_utc,
        terminal.challenge_sha256 == start.challenge_sha256,
        terminal.authorization_sha256 == start.authorization_sha256,
        terminal.policy_sha256 == start.policy_sha256,
        terminal.plan_sha256 == start.plan_sha256,
        _profile_binding_matches(terminal.profile_binding, accepted_b.packet),
        terminal.quota_contexts == start.quota_contexts,
        terminal.authorization_max_ttl_seconds == start.authorization_max_ttl_seconds,
        terminal.start_marker_sha256 == start.start_marker_sha256,
        operation.expires_at.isoformat().replace("+00:00", "Z")
        == terminal.authorization_expires_at_utc.isoformat().replace("+00:00", "Z"),
    )
    if not all(historical_checks):
        raise _fail("post_c_recovery_binding_mismatch")
    validate_partial_gate_c_semantics(
        terminal,
        accepted_b.packet,
        packet_auth,
        operation,
        trusted_anchor=_anchor(authorization),
        operation_sha256=authorization.operation_sha256,
        plan_sha256=authorization.plan_sha256,
    )
    try:
        source_configs = _source_configs(
            terminal.verified_sources, authorization.operation_sha256, terminal.requests
        )
        source_plan = build_source_plan(
            namespace=f"gate-c-recovery-{authorization.operation_id[:8]}-{authorization.plan_sha256[:8]}",
            root=authorization.recovery_root,
            per_board_cap=int(packet_auth["per_board_cap"]),
            per_company_cap=int(packet_auth["per_company_cap"]),
            budget=SourcePlanBudget(
                str(packet["gate_b_packet_sha256"]), int(packet_auth["budget_units"])
            ),
            seed=SeedInputs(accepted_b.packet.selection_seed, accepted_b.packet.partition_seed),
            operation_id=operation.operation_id,
            lineage_id=f"recovery-{packet_auth['lineage_id']}",
            source_configs=source_configs,
        )
    except Exception as exc:
        raise _fail("post_c_recovery_source_plan_invalid") from exc
    expected_evidence = _evidence_payload(terminal, source_plan)
    if evidence_raw.rstrip(b"\n") != expected_evidence:
        raise _fail("post_c_recovery_evidence_mismatch")
    if source_plan.source_plan_sha256 != authorization.source_plan_sha256:
        raise _fail("post_c_recovery_source_plan_hash_invalid")
    public = RecoveredGateCPublicResult(
        operation_id=terminal.operation_id,
        plan_sha256=terminal.plan_sha256,
        source_plan_sha256=source_plan.source_plan_sha256,
        report_sha256=terminal.report_sha256,
        query_count=len(
            {item.query_ordinal for item in terminal.requests if item.kind == "search"}
        ),
        host_count=len(terminal.verified_sources),
        family_counts={
            source.source_type: sum(
                1 for item in terminal.verified_sources if item.source_type == source.source_type
            )
            for source in terminal.verified_sources
        },
        budget_status=terminal.terminal_code or "",
        result=terminal.state,
        reason=terminal.terminal_code,
    )
    return RecoveredPostCData(
        authorization=authorization,
        gate_c_result=RecoveredGateCResult(public, source_plan, terminal),
        terminal=terminal,
        source_plan=source_plan,
        evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
        evidence_bytes=evidence_raw,
    )


def load_recovered_post_c(
    authorization: PostCAuthorization,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RecoveredPostCData:
    """Pin both immutable roots for the complete load and reconstruction."""

    if not isinstance(authorization, PostCAuthorization):
        raise _fail("post_c_recovery_authorization_invalid")
    clock = clock or (lambda: datetime.now(UTC))
    now = clock()
    if not isinstance(now, datetime):
        raise _fail("post_c_recovery_clock_invalid")
    try:
        with (
            pinned_root(Path(authorization.historical_root)) as historical_fd,
            pinned_root(Path(authorization.recovery_root)) as recovery_fd,
        ):
            return _load_recovered_post_c_pinned(authorization, historical_fd, recovery_fd, now=now)
    except (RecoveryFilesystemError, PostCRecoveryAuthorizationError) as exc:
        raise _fail(getattr(exc, "code", "post_c_recovery_load_failed")) from exc


__all__ = [
    "PostCRecoveryLoadError",
    "RecoveredGateCPublicResult",
    "RecoveredGateCResult",
    "RecoveredPostCData",
    "load_recovered_post_c",
]
