"""Pure authorization boundary for the offline R2 Gate F operation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from role_radar.evaluation.profile_relevance.contracts import (
    MaterializationContext,
    PreviewComputationResult,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    GateDResult,
    ParentPoolManifest,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import SyntheticTestAdapter
from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    AuthorizedGateE,
    GateEAuthorizationError,
    GateEAuthorizationRequest,
    authorize_gate_e,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import GateEPreviewRecord
from role_radar.evaluation.profile_relevant_acquisition.provenance import ProvenanceBundle

HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class GateFAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _hash(value: object, code: str) -> None:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise GateFAuthorizationError(code)


@dataclass(frozen=True, slots=True)
class GateFAuthorization:
    operation_id: str
    lineage_id: str
    challenge_sha256: str
    expires_at_utc: str
    artifact_class: str
    test_only_adapter: SyntheticTestAdapter


@dataclass(frozen=True, slots=True)
class GateFAuthorizationRequest:
    """Complete, explicit B→E graph.  No field is optional by design."""

    authorization: GateFAuthorization
    gate_e_request: GateEAuthorizationRequest
    gate_d_result: GateDResult
    parent_pool_manifest: ParentPoolManifest
    provenance: ProvenanceBundle
    profile_relevance_input: ProfileRelevanceInput
    gate_e_record: GateEPreviewRecord
    gate_e_result: PreviewComputationResult
    materialization_context: MaterializationContext
    dataset_id: str
    destination_root: Path


@dataclass(frozen=True, slots=True)
class AuthorizedGateF:
    request: GateFAuthorizationRequest
    gate_e: AuthorizedGateE


def authorize_gate_f(
    request: GateFAuthorizationRequest, *, now: datetime | None = None
) -> AuthorizedGateF:
    if not isinstance(request, GateFAuthorizationRequest):
        raise GateFAuthorizationError("gate_f_authorization_required")
    auth = request.authorization
    if not isinstance(auth, GateFAuthorization) or not isinstance(
        auth.test_only_adapter, SyntheticTestAdapter
    ):
        raise GateFAuthorizationError("gate_f_synthetic_adapter_required")
    if (
        type(auth.artifact_class) is not str
        or type(auth.operation_id) is not str
        or type(auth.lineage_id) is not str
        or auth.artifact_class != "synthetic"
        or not auth.operation_id.strip()
        or not auth.lineage_id.strip()
    ):
        raise GateFAuthorizationError("gate_f_authorization_invalid")
    _hash(auth.challenge_sha256, "gate_f_challenge_invalid")
    if type(auth.expires_at_utc) is not str or not auth.expires_at_utc.endswith("Z"):
        raise GateFAuthorizationError("gate_f_expiry_invalid")
    try:
        expiry = datetime.fromisoformat(auth.expires_at_utc[:-1] + "+00:00")
        clock = datetime.now(UTC) if now is None else now.astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise GateFAuthorizationError("gate_f_expiry_invalid") from exc
    if expiry.tzinfo is not UTC or clock >= expiry:
        raise GateFAuthorizationError("authorization_expired")
    if (
        type(request.dataset_id) is not str
        or not HEX64.fullmatch(request.dataset_id)
        or not isinstance(request.destination_root, Path)
        or not request.destination_root.is_absolute()
    ):
        raise GateFAuthorizationError("gate_f_destination_invalid")
    try:
        gate_e = authorize_gate_e(request.gate_e_request, now=clock)
    except GateEAuthorizationError as exc:
        raise GateFAuthorizationError(exc.code) from exc
    if gate_e.request.operation_id != auth.operation_id or gate_e.request.lineage_id != (
        auth.lineage_id
    ):
        raise GateFAuthorizationError("gate_f_operation_lineage_mismatch")
    if str(request.destination_root) != request.provenance.root:
        raise GateFAuthorizationError("gate_f_root_mismatch")
    if gate_e.request.gate_d_result is not request.gate_d_result or (
        gate_e.request.parent_pool_manifest is not request.parent_pool_manifest
    ):
        raise GateFAuthorizationError("gate_f_d_snapshot_substituted")
    if gate_e.request.provenance is not request.provenance or (
        gate_e.request.profile_relevance_input is not request.profile_relevance_input
    ):
        raise GateFAuthorizationError("gate_f_input_substituted")
    if not isinstance(request.gate_e_record, GateEPreviewRecord) or not isinstance(
        request.gate_e_result, PreviewComputationResult
    ):
        raise GateFAuthorizationError("gate_f_e_result_required")
    record = request.gate_e_record
    result = request.gate_e_result
    if request.provenance.provenance_sha256 != record.provenance_sha256:
        raise GateFAuthorizationError("gate_f_provenance_mismatch")
    result_hashes = (
        result.selection_sha256,
        result.partition_sha256,
        result.pilot_membership_sha256,
        result.holdout_membership_sha256,
    )
    record_hashes = (
        record.selection_sha256,
        record.partition_sha256,
        record.pilot_membership_sha256,
        record.holdout_membership_sha256,
    )
    if result_hashes != record_hashes:
        raise GateFAuthorizationError("gate_f_e_hash_mismatch")
    if not isinstance(request.materialization_context, MaterializationContext) or (
        request.materialization_context.inputs is not request.profile_relevance_input
    ):
        raise GateFAuthorizationError("gate_f_materialization_context_invalid")
    return AuthorizedGateF(request, gate_e)


__all__ = [
    "AuthorizedGateF",
    "GateFAuthorization",
    "GateFAuthorizationError",
    "GateFAuthorizationRequest",
    "authorize_gate_f",
]
