"""One-shot, offline-only R2 Gate C report-only service."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

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

__all__ = [
    "GateCPublicResult",
    "GateCResult",
    "GateCServiceError",
    "OfflineOfficialProvider",
    "execute_gate_c_report_only",
    "run_gate_c_report_only",
]
