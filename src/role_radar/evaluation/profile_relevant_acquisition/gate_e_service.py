"""The sole R2 Gate E authority: validate, preview once, sanitize, stop."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    GateEAuthorizationError,
    GateEAuthorizationRequest,
    authorize_gate_e,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_input_adapter import (
    adapt_gate_e_input,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import (
    GateEPreviewRecord,
    run_gate_e_preview,
)

PUBLIC_FIELDS = (
    "operation_id",
    "preregistration_sha256",
    "source_plan_sha256",
    "preview_input_sha256",
    "selection_sha256",
    "partition_sha256",
    "pilot_membership_sha256",
    "holdout_membership_sha256",
    "sanitized_preview_sha256",
    "provenance_sha256",
    "corpus_count",
    "pilot_count",
    "holdout_count",
    "feasibility",
    "status",
    "code",
)


@dataclass(frozen=True, slots=True)
class GateEPublicResult:
    operation_id: str
    preregistration_sha256: str
    source_plan_sha256: str
    preview_input_sha256: str
    selection_sha256: str | None
    partition_sha256: str | None
    pilot_membership_sha256: str | None
    holdout_membership_sha256: str | None
    sanitized_preview_sha256: str | None
    provenance_sha256: str
    corpus_count: int
    pilot_count: int
    holdout_count: int
    feasibility: str
    status: str
    code: str

    def as_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in PUBLIC_FIELDS}


@dataclass(frozen=True, slots=True)
class GateEPreviewOutcome:
    public: GateEPublicResult
    record: GateEPreviewRecord | None = None


def run_gate_e_offline_preview(
    *, authorization: GateEAuthorizationRequest, clock: Callable[[], datetime] | None = None
) -> GateEPreviewOutcome:
    try:
        authorized = authorize_gate_e(authorization, now=clock() if clock else None)
        inputs = adapt_gate_e_input(authorized)
        result, record = run_gate_e_preview(inputs=inputs, provenance=authorization.provenance)
        public = GateEPublicResult(
            operation_id=authorization.operation_id,
            preregistration_sha256=authorization.post_c_seal.preregistration_sha256,
            source_plan_sha256=authorization.post_c_request.source_plan.source_plan_sha256,
            preview_input_sha256=inputs.preview_input_sha256,
            selection_sha256=record.selection_sha256,
            partition_sha256=record.partition_sha256,
            pilot_membership_sha256=record.pilot_membership_sha256,
            holdout_membership_sha256=record.holdout_membership_sha256,
            sanitized_preview_sha256=record.sanitized_preview_sha256,
            provenance_sha256=record.provenance_sha256,
            corpus_count=len(result.selection.selected),
            pilot_count=len(result.partition.pilot_item_hashes),
            holdout_count=len(result.partition.holdout_item_hashes),
            feasibility="feasible",
            status="completed",
            code="gate_e_preview_completed",
        )
        return GateEPreviewOutcome(public, record)
    except GateEAuthorizationError:
        raise
    except Exception as exc:
        code = getattr(exc, "code", "gate_e_preview_infeasible")
        if isinstance(authorization, GateEAuthorizationRequest):
            public = GateEPublicResult(
                operation_id=authorization.operation_id,
                preregistration_sha256=authorization.post_c_seal.preregistration_sha256,
                source_plan_sha256=authorization.post_c_request.source_plan.source_plan_sha256,
                preview_input_sha256=getattr(
                    authorization.profile_relevance_input, "preview_input_sha256", ""
                ),
                selection_sha256=None,
                partition_sha256=None,
                pilot_membership_sha256=None,
                holdout_membership_sha256=None,
                sanitized_preview_sha256=None,
                provenance_sha256=authorization.provenance.provenance_sha256,
                corpus_count=0,
                pilot_count=0,
                holdout_count=0,
                feasibility="infeasible",
                status="blocked",
                code=str(code),
            )
            return GateEPreviewOutcome(public)
        raise GateEAuthorizationError("gate_e_authorization_required") from exc


run_gate_e_preview_authority = run_gate_e_offline_preview

__all__ = [
    "GateEPreviewOutcome",
    "GateEPublicResult",
    "run_gate_e_offline_preview",
    "run_gate_e_preview_authority",
]
