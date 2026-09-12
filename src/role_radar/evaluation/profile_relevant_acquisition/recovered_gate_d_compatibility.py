"""Pure compatibility assessment; deliberately cannot execute Gate D."""

from __future__ import annotations

from dataclasses import dataclass

from .recovered_gate_d_authorization import RecoveredGateDPreflightAuthorization

REASONS = (
    "ordinary_post_c_request_identity_required",
    "ordinary_post_c_build_seal_required",
    "completed_predecessor_required",
    "normal_c_provenance_required",
)


@dataclass(frozen=True, slots=True)
class RecoveredGateDPreflightVerdict:
    version: str
    result: str
    code: str
    operation_id: str
    source_plan_sha256: str
    report_sha256: str
    seal_sha256: str
    authorization_digest: str
    expected_source_count: int
    predecessor_state: str
    predecessor_terminal: str
    gate_d_compatibility_reasons: tuple[str, ...]
    effect: str = "disabled"
    downstream: str = "disabled"

    def as_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def assess_recovered_gate_d_compatibility(
    authorization: RecoveredGateDPreflightAuthorization,
    *,
    predecessor_state: str,
    predecessor_terminal: str,
    source_count: int,
) -> RecoveredGateDPreflightVerdict:
    reasons_list = [
        "ordinary_post_c_request_identity_required",
        "ordinary_post_c_build_seal_required",
    ]
    if predecessor_state != "completed":
        reasons_list.append("completed_predecessor_required")
    if predecessor_terminal != "" or source_count != 6:
        reasons_list.append("normal_c_provenance_required")
    reasons = tuple(reason for reason in REASONS if reason in reasons_list)
    return RecoveredGateDPreflightVerdict(
        version="f10.1f-gate-d-recovered-preflight-v1",
        result="blocked",
        code="gate_d_recovered_predecessor_incompatible",
        operation_id=authorization.operation_id,
        source_plan_sha256=authorization.source_plan_sha256,
        report_sha256=authorization.report_sha256,
        seal_sha256=authorization.seal_sha256,
        authorization_digest=authorization.post_c_authorization_sha256,
        expected_source_count=source_count,
        predecessor_state=predecessor_state,
        predecessor_terminal=predecessor_terminal,
        gate_d_compatibility_reasons=reasons,
    )


__all__ = ["RecoveredGateDPreflightVerdict", "assess_recovered_gate_d_compatibility"]
