"""One-shot, offline-only R2 Gate C report-only service."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    ReportOnlyRequestEvidenceV1,
    ReportOnlyVerifiedSourceV1,
)
from role_radar.discovery.authorization_v2 import canonical_json_bytes
from role_radar.discovery.board_candidates import BoardCandidateV2
from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2
from role_radar.evaluation.profile_relevant_acquisition.contracts import SeedInputs
from role_radar.evaluation.profile_relevant_acquisition.discovery_runtime import (
    ReportOnlyResult,
    ReportOnlyRuntimeConfig,
    persist_private_evidence,
    run_report_only_discovery,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCAuthorizationError,
    authorize_gate_c,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_capability import (
    ApprovedRealDiscoveryCapability,
    RealDiscoveryCapabilityError,
)
from role_radar.evaluation.profile_relevant_acquisition.real_gate_c_discovery import (
    MAX_REAL_POSTINGS,
    MAX_REAL_UNIQUE_BOARD_CANDIDATES,
    RealDiscoveryResult,
    has_usable_real_discovery_result,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    SourcePlan,
    SourcePlanBudget,
    SourcePlanError,
    build_source_plan,
)
from role_radar.sources.identity import canonical_source_key


class OfflineOfficialProvider(Protocol):
    offline: bool

    def official_board_configurations(
        self, plan: DiscoveryQueryPlanV2
    ) -> Sequence[BoardCandidateV2]: ...


class GateCServiceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GateCPublicResult:
    """The complete public result allowlist; private details stay in service state."""

    operation_id: str
    plan_sha256: str
    source_plan_sha256: str | None
    report_sha256: str | None
    query_count: int
    host_count: int
    family_counts: Mapping[str, int]
    budget_status: str
    result: str
    reason: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "plan_sha256": self.plan_sha256,
            "source_plan_sha256": self.source_plan_sha256,
            "report_sha256": self.report_sha256,
            "query_count": self.query_count,
            "host_count": self.host_count,
            "family_counts": dict(self.family_counts),
            "budget_status": self.budget_status,
            "result": self.result,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class GateCResult:
    public: GateCPublicResult
    source_plan: SourcePlan | None
    report: ReportOnlyResult | None


def _official_configs(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise GateCServiceError("official_board_configuration_invalid")
    output: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for candidate in value:
        if not isinstance(candidate, BoardCandidateV2):
            raise GateCServiceError("official_board_configuration_invalid")
        if candidate.source_type not in {"greenhouse", "lever"}:
            raise GateCServiceError("official_board_configuration_non_official")
        config = dict(candidate.configuration)
        try:
            expected_key = canonical_source_key(candidate.source_type, config)
        except (TypeError, ValueError) as exc:
            raise GateCServiceError("official_board_configuration_invalid") from exc
        if expected_key != candidate.source_key or candidate.source_key in seen:
            raise GateCServiceError("official_board_configuration_substituted")
        seen.add(candidate.source_key)
        output.append(
            {
                "family": candidate.source_type,
                "source_key": candidate.source_key,
                "configuration_version": 1,
                "configuration": config,
            }
        )
    if not output:
        raise GateCServiceError("official_board_configuration_missing")
    return tuple(output)


def _make_source_plan(
    auth: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    configs: tuple[Mapping[str, object], ...],
) -> SourcePlan:
    try:
        seed = SeedInputs(
            selection_seed=accepted_b.packet.selection_seed,
            partition_seed=accepted_b.packet.partition_seed,
        )
        return build_source_plan(
            namespace=auth.provenance.namespace,
            root=auth.provenance.approved_root,
            per_board_cap=auth.per_board_cap,
            per_company_cap=auth.per_company_cap,
            budget=SourcePlanBudget(auth.provenance.gate_b_packet_sha256, auth.budget_units),
            seed=seed,
            operation_id=auth.operation_id,
            lineage_id=auth.lineage_id,
            source_configs=configs,
        )
    except (SourcePlanError, TypeError, ValueError) as exc:
        raise GateCServiceError(getattr(exc, "code", "source_plan_invalid")) from exc


def execute_gate_c_report_only(
    *,
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: DiscoveryQueryPlanV2,
    provider: OfflineOfficialProvider,
    evidence_root: Path,
    before_after: Any = None,
    ledger_reconcile: Any = None,
) -> GateCResult:
    """Authorize, perform exactly one injected offline operation, then stop."""
    try:
        authorize_gate_c(authorization, accepted_b, plan)
    except GateCAuthorizationError:
        raise
    if not isinstance(evidence_root, Path) or evidence_root != Path(
        authorization.provenance.approved_root
    ):
        raise GateCServiceError("root_mismatch")
    if getattr(provider, "offline", False) is not True or not callable(
        getattr(provider, "official_board_configurations", None)
    ):
        raise GateCServiceError("offline_provider_required")

    try:
        configs = _official_configs(provider.official_board_configurations(plan))
        source_plan = _make_source_plan(authorization, accepted_b, configs)
        report = run_report_only_discovery(
            plan=plan,
            config=ReportOnlyRuntimeConfig(
                evidence_root=evidence_root,
                before_after=before_after,
                ledger_reconcile=ledger_reconcile,
            ),
            expected_plan_sha256=authorization.provenance.query_plan_sha256,
        )
        persist_private_evidence(report, evidence_root)
    except GateCServiceError:
        raise
    except Exception as exc:
        raise GateCServiceError(getattr(exc, "code", "gate_c_report_failed")) from exc

    counts = report.sanitized_counts
    public = GateCPublicResult(
        operation_id=authorization.operation_id,
        plan_sha256=report.plan_sha256,
        source_plan_sha256=source_plan.source_plan_sha256,
        report_sha256=report.report_sha256,
        query_count=report.query_count,
        host_count=counts.get("host_count", 0),
        family_counts={key: value for key, value in counts.items() if key.startswith("family_")},
        budget_status="within_bound",
        result="completed",
        reason=None,
    )
    return GateCResult(public, source_plan, report)


run_gate_c_report_only = execute_gate_c_report_only


def _verified_source_configs(
    sources: object,
    *,
    operation_id: str,
    operation_sha256: str,
    plan_sha256: str,
    requests: object,
) -> tuple[Mapping[str, object], ...]:
    """Convert verified report-only sources to canonical plan configurations.

    Only structurally successful official verifications cross this boundary.
    Search payloads, job material, and provider internals never do.
    """

    if (
        not isinstance(sources, tuple)
        or not sources
        or not isinstance(requests, tuple)
        or not requests
    ):
        raise GateCServiceError("official_board_configuration_missing")
    if not all(isinstance(request, ReportOnlyRequestEvidenceV1) for request in requests):
        raise GateCServiceError("official_board_configuration_invalid")
    output: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, ReportOnlyVerifiedSourceV1):
            raise GateCServiceError("official_board_configuration_invalid")
        if source.source_type not in {"greenhouse", "lever"}:
            raise GateCServiceError("official_board_configuration_non_official")
        config = dict(source.configuration)
        try:
            expected_key = canonical_source_key(source.source_type, config)
        except (TypeError, ValueError) as exc:
            raise GateCServiceError("official_board_configuration_invalid") from exc
        if (
            expected_key != source.source_key
            or source.source_key in seen
            or len(config) != len(source.configuration)
        ):
            raise GateCServiceError("official_board_configuration_substituted")
        expected_configuration_sha = hashlib.sha256(canonical_json_bytes(config)).hexdigest()
        if (
            expected_configuration_sha != source.configuration_sha256
            or not 1 <= source.board_candidate_ordinal <= MAX_REAL_UNIQUE_BOARD_CANDIDATES
            or not 0 <= source.postings_count <= MAX_REAL_POSTINGS
            or source.request_identity_sha256 == "0" * 64
        ):
            raise GateCServiceError("official_board_configuration_invalid")
        destination = (
            "greenhouse_official_api"
            if source.source_type == "greenhouse"
            else "lever_eu_official_api"
            if config.get("region") == "eu"
            else "lever_global_official_api"
        )
        matches = [
            request
            for request in requests
            if request.kind == "official_verification"
            and request.board_candidate_ordinal == source.board_candidate_ordinal
        ]
        if len(matches) != 1:
            raise GateCServiceError("official_board_configuration_invalid")
        request = matches[0]
        expected_wire_key = (
            f"cdv2:{operation_id}:{plan_sha256}:"
            f"b{source.board_candidate_ordinal:02d}:w001:{source.source_type}"
        )
        expected_identity = hashlib.sha256(
            canonical_json_bytes(
                {
                    "operation_sha256": operation_sha256,
                    "source_type": source.source_type,
                    "source_key": source.source_key,
                    "configuration_sha256": expected_configuration_sha,
                    "destination": destination,
                    "board_candidate_ordinal": source.board_candidate_ordinal,
                    "wire_attempt_ordinal": 1,
                    "collector_request_ordinal": 1,
                }
            )
        ).hexdigest()
        if (
            request.provider != source.source_type
            or request.destination != destination
            or request.operation_key_sha256
            != hashlib.sha256(expected_wire_key.encode("utf-8")).hexdigest()
            or request.request_identity_sha256 != expected_identity
            or source.request_identity_sha256 != expected_identity
            or request.transmission != "sent"
            or request.outcome != "succeeded"
            or request.collector_request_ordinal != 1
            or request.wire_attempt_ordinal != 1
            or request.postings_count != source.postings_count
        ):
            raise GateCServiceError("official_board_configuration_invalid")
        seen.add(source.source_key)
        output.append(
            {
                "family": source.source_type,
                "source_key": source.source_key,
                "configuration_version": 1,
                "configuration": config,
            }
        )
    return tuple(output)


def _validate_request_evidence(result: RealDiscoveryResult) -> None:
    requests = result.requests
    counts = result.counts
    if not isinstance(counts, Mapping) or not requests:
        raise GateCServiceError("real_discovery_request_evidence_invalid")
    if tuple(request.request_ordinal for request in requests) != tuple(range(1, len(requests) + 1)):
        raise GateCServiceError("real_discovery_request_evidence_invalid")
    if len({request.request_identity_sha256 for request in requests}) != len(requests):
        raise GateCServiceError("real_discovery_request_evidence_invalid")
    search = tuple(request for request in requests if request.kind == "search")
    official = tuple(request for request in requests if request.kind == "official_verification")
    if (
        len(search) != counts["search_requests_attempted"]
        or len(official) != counts["board_verifications_attempted"]
        or len(official) != counts["verification_wire_attempts_consumed"]
        or sum(request.known_count for request in requests) != counts["classified_hits"]
        or sum(
            request.outcome in {"succeeded", "empty", "failed", "malformed"} for request in requests
        )
        != counts["search_requests_completed"]
        or any(
            request.request_identity_sha256 == "0" * 64 or request.operation_key_sha256 == "0" * 64
            for request in requests
        )
        or any(
            request.transmission != "sent" or request.outcome not in {"succeeded", "failed"}
            for request in official
        )
        or any(
            request.result_count != 0
            or request.known_count != 0
            or request.unknown_count != 0
            or request.rejected_count != 0
            or request.postings_count != 0
            or request.collector_request_ordinal != 1
            or request.wire_attempt_ordinal != 1
            for request in official
        )
    ):
        raise GateCServiceError("real_discovery_request_evidence_invalid")
    for request in requests:
        if request.kind == "search":
            if (
                request.identity_query_sha256 is None
                or request.identity_max_results is None
                or request.query_ordinal is None
            ):
                raise GateCServiceError("real_discovery_request_evidence_invalid")
            expected_identity = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "operation_sha256": result.operation_sha256,
                        "plan_sha256": result.plan_sha256,
                        "provider": request.provider,
                        "destination": request.destination,
                        "query_ordinal": request.query_ordinal,
                        "query_sha256": request.identity_query_sha256,
                        "max_results": request.identity_max_results,
                    }
                )
            ).hexdigest()
        else:
            if (
                request.identity_source_key is None
                or request.identity_configuration_sha256 is None
                or request.board_candidate_ordinal is None
                or request.collector_request_ordinal != 1
                or request.wire_attempt_ordinal != 1
            ):
                raise GateCServiceError("real_discovery_request_evidence_invalid")
            destination = request.destination
            expected_wire_key = (
                f"cdv2:{result.operation_id}:{result.plan_sha256}:"
                f"b{request.board_candidate_ordinal:02d}:w001:{request.provider}"
            )
            if (
                request.operation_key_sha256
                != hashlib.sha256(expected_wire_key.encode("utf-8")).hexdigest()
            ):
                raise GateCServiceError("real_discovery_request_evidence_invalid")
            expected_identity = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "operation_sha256": result.operation_sha256,
                        "source_type": request.provider,
                        "source_key": request.identity_source_key,
                        "configuration_sha256": request.identity_configuration_sha256,
                        "destination": destination,
                        "board_candidate_ordinal": request.board_candidate_ordinal,
                        "wire_attempt_ordinal": request.wire_attempt_ordinal,
                        "collector_request_ordinal": request.collector_request_ordinal,
                    }
                )
            ).hexdigest()
        if request.request_identity_sha256 != expected_identity:
            raise GateCServiceError("real_discovery_request_evidence_invalid")


def _persist_real_discovery_evidence(
    result: RealDiscoveryResult,
    source_plan: SourcePlan,
    root: Path,
    *,
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: DiscoveryQueryPlanV2,
) -> Path:
    """Persist only a result revalidated at the Gate C persistence boundary."""

    from role_radar.evaluation.filesystem import (
        atomic_write,
        ensure_private_root,
    )

    if (
        type(result) is not RealDiscoveryResult
        or type(source_plan) is not SourcePlan
        or type(authorization) is not GateCAuthorization
        or type(accepted_b) is not AcceptedGateBBinding
        or type(plan) is not DiscoveryQueryPlanV2
    ):
        raise GateCServiceError("real_discovery_evidence_invalid")
    if result.operation_id != authorization.operation_id or result.plan_sha256 != plan.plan_sha256:
        raise GateCServiceError("real_discovery_binding_mismatch")
    if not has_usable_real_discovery_result(
        result.state,
        result.verified_sources,
        result.terminal_code,
        counts=result.counts,
        truncation=result.truncation,
        query_count=result.query_count,
        brave_requests=result.brave_requests,
        tavily_requests=result.tavily_requests,
        candidates_seen=result.candidates_seen,
        verifications_attempted=result.verifications_attempted,
        wire_attempts_consumed=result.wire_attempts_consumed,
    ):
        raise GateCServiceError("real_discovery_evidence_invalid")
    _validate_request_evidence(result)
    configs = _verified_source_configs(
        result.verified_sources,
        operation_id=result.operation_id,
        operation_sha256=result.operation_sha256,
        plan_sha256=result.plan_sha256,
        requests=result.requests,
    )
    expected_source_plan = _make_source_plan(authorization, accepted_b, configs)
    if expected_source_plan.source_plan_sha256 != source_plan.source_plan_sha256:
        raise GateCServiceError("real_discovery_evidence_invalid")
    plan_sha = result.plan_sha256
    report_sha = result.report_sha256
    verified = result.verified_sources
    entries: list[dict[str, object]] = []
    for source in verified:
        if not isinstance(source, ReportOnlyVerifiedSourceV1):
            raise GateCServiceError("real_discovery_evidence_invalid")
        entries.append(
            {
                "family": source.source_type,
                "source_key": source.source_key,
                "configuration": dict(source.configuration),
                "configuration_sha256": source.configuration_sha256,
                "postings_count": source.postings_count,
                "board_candidate_ordinal": source.board_candidate_ordinal,
                "request_identity_sha256": source.request_identity_sha256,
            }
        )
    ensure_private_root(root)
    evidence_dir = root / "gate-c" / plan_sha
    evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        evidence_dir.chmod(0o700)
    except OSError as exc:
        raise GateCServiceError("real_discovery_persist_failed") from exc
    import json

    try:
        payload = json.dumps(
            {
                "plan_sha256": plan_sha,
                "report_sha256": report_sha,
                "source_plan_sha256": source_plan.source_plan_sha256,
                "verified_sources": entries,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GateCServiceError("real_discovery_persist_failed") from exc
    target = evidence_dir / "real_discovery_evidence.json"
    try:
        atomic_write(target, payload)
    except Exception as exc:
        raise GateCServiceError("real_discovery_persist_failed") from exc
    return target


def persist_real_discovery_evidence(*args: Any, **kwargs: Any) -> Path:
    """Keep the historical import name without restoring the bypass.

    Persistence is only safe with the complete authorization, Gate B binding,
    and query plan context supplied by the execution path.  Callers using the
    former three-argument API must fail closed rather than bypass validation.
    """

    required = {"authorization", "accepted_b", "plan"}
    if (
        len(args) != 3
        or set(kwargs) != required
        or not all(
            type(kwargs[name]) is expected
            for name, expected in (
                ("authorization", GateCAuthorization),
                ("accepted_b", AcceptedGateBBinding),
                ("plan", DiscoveryQueryPlanV2),
            )
        )
    ):
        raise GateCServiceError("real_discovery_persistence_context_required")
    if type(args[0]) is not RealDiscoveryResult or type(args[1]) is not SourcePlan:
        raise GateCServiceError("real_discovery_persistence_context_required")
    return _persist_real_discovery_evidence(
        args[0],
        args[1],
        args[2],
        authorization=kwargs["authorization"],
        accepted_b=kwargs["accepted_b"],
        plan=kwargs["plan"],
    )


class RealDiscoveryRunner(Protocol):
    """Zero-argument real discovery thunk.

    The thunk takes no board, configuration, or plan argument: boards are
    discovered inside the authorized operation, never supplied by the caller.
    Only the reviewed composition may implement this protocol.
    """

    async def __call__(self) -> RealDiscoveryResult: ...


async def execute_gate_c_real_discovery(
    *,
    authorization: GateCAuthorization,
    accepted_b: AcceptedGateBBinding,
    plan: DiscoveryQueryPlanV2,
    config: object,
    capability: object,
    discover: RealDiscoveryRunner,
    evidence_root: Path,
    before_after: Any = None,
    now: Any = None,
) -> GateCResult:
    """Validate all bindings, invoke one real discovery thunk, then stop.

    This service converts only verified configurations into the canonical
    ``SourcePlan`` and never invokes Post-C or D.
    """

    from datetime import UTC, datetime

    if not isinstance(authorization, GateCAuthorization) or not isinstance(
        accepted_b, AcceptedGateBBinding
    ):
        raise GateCServiceError("gate_c_authorization_required")
    if not isinstance(plan, DiscoveryQueryPlanV2):
        raise GateCServiceError("gate_c_plan_invalid")
    if type(capability) is not ApprovedRealDiscoveryCapability:
        raise GateCServiceError("real_discovery_capability_required")
    if not callable(discover):
        raise GateCServiceError("real_discovery_runner_required")
    if not isinstance(evidence_root, Path) or evidence_root != Path(
        authorization.provenance.approved_root
    ):
        raise GateCServiceError("root_mismatch")
    check_at = now.astimezone(UTC) if isinstance(now, datetime) else datetime.now(UTC)
    try:
        authorize_gate_c(authorization, accepted_b, plan, now=check_at)
    except GateCAuthorizationError:
        raise
    try:
        capability.verify_for(authorization, accepted_b, plan, config, now=check_at)
    except RealDiscoveryCapabilityError as exc:
        raise GateCServiceError(getattr(exc, "code", "real_discovery_capability_rejected")) from exc

    before: dict[str, Any] | None = None
    if before_after is not None:
        before, _ = (dict(item) for item in before_after())
    try:
        result = await discover()
    except GateCServiceError:
        raise
    except Exception as exc:
        raise GateCServiceError(getattr(exc, "code", "real_discovery_failed")) from exc
    if before_after is not None:
        _, after = before_after()
        if before != dict(after):
            raise GateCServiceError("real_discovery_product_mutation_detected")

    if type(result) is not RealDiscoveryResult:
        raise GateCServiceError("real_discovery_result_invalid")
    if result.operation_id != authorization.operation_id or result.plan_sha256 != plan.plan_sha256:
        raise GateCServiceError("real_discovery_binding_mismatch")
    state = result.state
    verified = result.verified_sources
    if not has_usable_real_discovery_result(
        state,
        verified,
        result.terminal_code,
        counts=result.counts,
        truncation=result.truncation,
        query_count=result.query_count,
        brave_requests=result.brave_requests,
        tavily_requests=result.tavily_requests,
        candidates_seen=result.candidates_seen,
        verifications_attempted=result.verifications_attempted,
        wire_attempts_consumed=result.wire_attempts_consumed,
    ):
        raise GateCServiceError("real_discovery_no_verified_boards")
    if len(verified) > 8:
        raise GateCServiceError("real_discovery_result_invalid")
    _validate_request_evidence(result)
    configs = _verified_source_configs(
        verified,
        operation_id=result.operation_id,
        operation_sha256=result.operation_sha256,
        plan_sha256=result.plan_sha256,
        requests=result.requests,
    )
    source_plan = _make_source_plan(authorization, accepted_b, configs)
    _persist_real_discovery_evidence(
        result,
        source_plan,
        evidence_root,
        authorization=authorization,
        accepted_b=accepted_b,
        plan=plan,
    )

    family_counts: dict[str, int] = {}
    for item in configs:
        family_counts[f"family_{item['family']}"] = (
            family_counts.get(f"family_{item['family']}", 0) + 1
        )
    public = GateCPublicResult(
        operation_id=authorization.operation_id,
        plan_sha256=plan.plan_sha256,
        source_plan_sha256=source_plan.source_plan_sha256,
        report_sha256=getattr(result, "report_sha256", None),
        query_count=len(plan.queries),
        host_count=len(plan.source_registry),
        family_counts=family_counts,
        budget_status=("bounded_partial" if state == "completed_partial" else "within_bound"),
        result=state,
        reason=(result.terminal_code if state == "completed_partial" else None),
    )
    return GateCResult(public, source_plan, None)


__all__ = [
    "GateCPublicResult",
    "GateCResult",
    "GateCServiceError",
    "OfflineOfficialProvider",
    "RealDiscoveryRunner",
    "execute_gate_c_real_discovery",
    "execute_gate_c_report_only",
    "persist_real_discovery_evidence",
    "run_gate_c_report_only",
]
