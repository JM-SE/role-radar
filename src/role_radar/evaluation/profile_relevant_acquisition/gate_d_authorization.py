"""Pure, fail-closed authorization boundary for R2 Gate D.

This module intentionally has no filesystem, database, provider, or transport
side effects.  The Post-C request graph is the authority; the request object
and seal are never reconstructed from partial/defaulted dictionaries here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from role_radar.evaluation.profile_relevant_acquisition.acquisition_preregistration import (
    AcquisitionPreregistration,
)
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    AcquisitionScaffoldConfig,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    SeedInputs,
    SyntheticTestAdapter,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    PostCPreregistrationError,
    PostCPreregistrationRequest,
    PostCPreregistrationSeal,
    build_seal,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import SourcePlan

HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
SCHEMA_VERSION = "f10.1f-gate-d-authorization-v1"


class GateDAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _hash(value: object, code: str) -> None:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise GateDAuthorizationError(code)


def _utc(value: object, code: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise GateDAuthorizationError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GateDAuthorizationError(code) from exc
    if parsed.tzinfo is not UTC:
        raise GateDAuthorizationError(code)
    return parsed


@dataclass(frozen=True, slots=True)
class GateDAuthorizationRequest:
    """Complete explicit binding set for one named offline operation."""

    operation_id: str
    lineage_id: str
    post_c_request: PostCPreregistrationRequest
    post_c_seal: PostCPreregistrationSeal
    current_commit_sha256: str
    evidence_root: Path
    namespace: str
    window_start_utc: str
    window_end_utc: str
    cutoff_utc: str
    seeds: SeedInputs
    per_board_cap: int
    per_company_cap: int
    quotas: Mapping[str, int]
    cardinality: Mapping[str, int]
    budget_id: str
    budget_units: int
    artifact_class: str
    test_only_adapter: SyntheticTestAdapter


@dataclass(frozen=True, slots=True)
class AuthorizedGateD:
    request: GateDAuthorizationRequest
    preregistration: AcquisitionPreregistration
    scaffold: AcquisitionScaffoldConfig


def _provenance_hash(request: PostCPreregistrationRequest) -> str:
    fields = request.provenance.__dataclass_fields__
    payload = {name: getattr(request.provenance, name) for name in fields}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def authorize_gate_d(request: GateDAuthorizationRequest) -> AuthorizedGateD:
    """Validate every Gate D binding before an effect-capable object exists."""
    if not isinstance(request, GateDAuthorizationRequest):
        raise GateDAuthorizationError("gate_d_request_invalid")
    if not request.operation_id.strip() or not request.lineage_id.strip():
        raise GateDAuthorizationError("gate_d_operation_lineage_invalid")
    post = request.post_c_request
    if not isinstance(post, PostCPreregistrationRequest):
        raise GateDAuthorizationError("gate_d_post_c_required")
    if not isinstance(request.post_c_seal, PostCPreregistrationSeal):
        raise GateDAuthorizationError("gate_d_post_c_seal_invalid")
    try:
        expected = build_seal(post)
    except (PostCPreregistrationError, TypeError, ValueError) as exc:
        raise GateDAuthorizationError("gate_d_post_c_invalid") from exc
    if request.post_c_seal != expected:
        raise GateDAuthorizationError("gate_d_post_c_seal_mismatch")
    if expected.operation_id != request.operation_id or post.lineage_id != request.lineage_id:
        raise GateDAuthorizationError("gate_d_operation_lineage_mismatch")
    if post.authorization.gate != "C" or post.authorization.mode != "report-only":
        raise GateDAuthorizationError("gate_d_wrong_predecessor_gate")
    plan = post.source_plan
    if not isinstance(plan, SourcePlan) or post.gate_c_result.source_plan is not plan:
        raise GateDAuthorizationError("gate_d_source_plan_substituted")
    if plan.operation_id != request.operation_id or plan.lineage_id != request.lineage_id:
        raise GateDAuthorizationError("gate_d_source_plan_binding_mismatch")
    _hash(request.current_commit_sha256, "gate_d_current_commit_invalid")
    if request.current_commit_sha256 != post.provenance.candidate_commit_sha256:
        raise GateDAuthorizationError("gate_d_current_commit_mismatch")
    if request.evidence_root != Path(plan.root) or not request.evidence_root.is_absolute():
        raise GateDAuthorizationError("gate_d_root_mismatch")
    if request.namespace != plan.namespace:
        raise GateDAuthorizationError("gate_d_namespace_mismatch")
    start, end, cutoff = (
        _utc(v, "gate_d_window_invalid")
        for v in (request.window_start_utc, request.window_end_utc, request.cutoff_utc)
    )
    request_window = (
        request.window_start_utc,
        request.window_end_utc,
        request.cutoff_utc,
    )
    post_window = (
        post.provenance.window_start_utc,
        post.provenance.window_end_utc,
        post.provenance.cutoff_utc,
    )
    if not start < cutoff <= end or request_window != post_window:
        raise GateDAuthorizationError("gate_d_window_mismatch")
    if request.seeds != post.seeds or request.seeds != plan.seed:
        raise GateDAuthorizationError("gate_d_seed_mismatch")
    if (request.per_board_cap, request.per_company_cap) != (
        plan.per_board_cap,
        plan.per_company_cap,
    ):
        raise GateDAuthorizationError("gate_d_cap_mismatch")
    if request.budget_id != plan.budget.budget_id or request.budget_units != plan.budget.maximum:
        raise GateDAuthorizationError("gate_d_budget_mismatch")
    if type(request.budget_units) is not int or request.budget_units <= 0:
        raise GateDAuthorizationError("gate_d_finite_budget_required")
    if request.artifact_class != "offline_private_report_only":
        raise GateDAuthorizationError("gate_d_artifact_class_invalid")
    if not isinstance(request.test_only_adapter, SyntheticTestAdapter):
        raise GateDAuthorizationError("gate_d_synthetic_adapter_required")
    expected_cardinality = {
        "corpus": post.target_corpus_count,
        "pilot": post.target_pilot_count,
        "holdout": post.target_holdout_count,
    }
    if dict(request.cardinality) != expected_cardinality:
        raise GateDAuthorizationError("gate_d_cardinality_mismatch")
    if any(type(v) is not int or v < 0 for v in request.quotas.values()):
        raise GateDAuthorizationError("gate_d_quota_invalid")
    if dict(request.quotas) != dict(post.query_plan.limits):
        raise GateDAuthorizationError("gate_d_quota_mismatch")
    prereg = AcquisitionPreregistration(
        request.operation_id,
        plan.source_plan_sha256,
        _provenance_hash(post),
        expected.preregistration_sha256,
    )
    scaffold = AcquisitionScaffoldConfig(
        request.evidence_root,
        request.operation_id,
        prereg.provenance_sha256,
        prereg.preregistration_sha256,
        plan.source_plan_sha256,
        request.budget_id,
        request.namespace,
    )
    return AuthorizedGateD(request, prereg, scaffold)


__all__ = [
    "SCHEMA_VERSION",
    "AuthorizedGateD",
    "GateDAuthorizationError",
    "GateDAuthorizationRequest",
    "authorize_gate_d",
]
