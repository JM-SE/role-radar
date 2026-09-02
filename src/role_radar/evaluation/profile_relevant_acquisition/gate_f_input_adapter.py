"""Pure conversion of the already verified D/E graph to F10.1E inputs."""

from __future__ import annotations

from role_radar.evaluation.profile_relevance.contracts import (
    MaterializationContext,
    ProfileRelevanceInput,
)
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
        if not left.canonical_observation_bytes:
            raise GateFAuthorizationError("gate_f_observation_unsealed")
    record = request.gate_e_record
    if inputs.preview_input_sha256 != record.preview_input_sha256:
        raise GateFAuthorizationError("gate_f_preview_binding_mismatch")
    if request.materialization_context.expected_approved_preview is None:
        raise GateFAuthorizationError("gate_f_approved_preview_required")
    return inputs, request.materialization_context


__all__ = ["adapt_gate_f_input"]
