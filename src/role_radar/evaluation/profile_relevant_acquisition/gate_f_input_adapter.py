"""Pure conversion of the already verified D/E graph to F10.1E inputs."""

from __future__ import annotations

import re

from role_radar.evaluation.profile_relevance.contracts import (
    MaterializationContext,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import build_gate_e_record
from role_radar.evaluation.profile_relevant_acquisition.gate_f_authorization import (
    AuthorizedGateF,
    GateFAuthorizationError,
)


def adapt_gate_f_input(
    authorized: AuthorizedGateF,
) -> tuple[ProfileRelevanceInput, MaterializationContext]:
    if not isinstance(authorized, AuthorizedGateF):
        raise GateFAuthorizationError("gate_f_authorization_required")
    request = authorized.request
    inputs = request.profile_relevance_input
    snapshot = inputs.sealed_snapshot
    result = request.gate_d_result
    manifest = request.parent_pool_manifest
    if manifest is not result.manifest:
        raise GateFAuthorizationError("gate_f_manifest_substituted")
    if manifest.source_plan_sha256 != snapshot.source_plan_sha256:
        raise GateFAuthorizationError("gate_f_source_plan_mismatch")
    if manifest.pool_sha256 != result.pool_sha256 or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in (manifest.pool_sha256, manifest.source_plan_sha256, manifest.provenance_sha256)
    ):
        raise GateFAuthorizationError("gate_f_pool_binding_mismatch")
    if snapshot.state != "sealed" or len(snapshot.observations) != len(result.observations):
        raise GateFAuthorizationError("gate_f_snapshot_invalid")
    for left, right in zip(snapshot.observations, result.observations, strict=True):
        left_values = (
            left.observation_id,
            left.source.source_id,
            left.source.board_key,
            left.title,
            left.location,
            left.description,
        )
        right_values = (
            right.external_id,
            right.source_id,
            right.source_key,
            right.title,
            right.location or "",
            right.description or "",
        )
        if left_values != right_values:
            raise GateFAuthorizationError("gate_f_observation_substituted")
        if not left.canonical_observation_bytes or not isinstance(
            left.canonical_observation_bytes, bytes
        ):
            raise GateFAuthorizationError("gate_f_observation_unsealed")
    record = request.gate_e_record
    preview = request.gate_e_result
    if (
        build_gate_e_record(
            result=preview,
            inputs=inputs,
            provenance=request.provenance,
        )
        != record
    ):
        raise GateFAuthorizationError("gate_f_e_record_noncanonical")
    if (
        preview.selection_sha256 != record.selection_sha256
        or preview.partition_sha256 != record.partition_sha256
        or preview.pilot_membership_sha256 != record.pilot_membership_sha256
        or preview.holdout_membership_sha256 != record.holdout_membership_sha256
    ):
        raise GateFAuthorizationError("gate_f_e_result_identity_mismatch")
    if inputs.preview_input_sha256 != record.preview_input_sha256:
        raise GateFAuthorizationError("gate_f_preview_binding_mismatch")
    if request.materialization_context.expected_approved_preview is None:
        raise GateFAuthorizationError("gate_f_approved_preview_required")
    return inputs, request.materialization_context


__all__ = ["adapt_gate_f_input"]
