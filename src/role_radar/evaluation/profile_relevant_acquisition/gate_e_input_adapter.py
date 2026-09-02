"""Verified conversion seam for Gate D's sealed observation snapshot."""

from __future__ import annotations

from dataclasses import replace

from role_radar.evaluation.profile_relevance.contracts import ProfileRelevanceInput
from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    AuthorizedGateE,
    GateEAuthorizationError,
)


def adapt_gate_e_input(authorized: AuthorizedGateE) -> ProfileRelevanceInput:
    """Return only the supplied, chain-bound input template.

    The template is not accepted by the public service: authorization proves its
    provenance and exact Gate D snapshot identity first.  ``replace`` creates a
    fresh immutable DTO so callers cannot mutate the authorization graph.
    """

    if not isinstance(authorized, AuthorizedGateE):
        raise GateEAuthorizationError("gate_e_authorization_required")
    value = authorized.request.profile_relevance_input
    if not isinstance(value, ProfileRelevanceInput):
        raise GateEAuthorizationError("gate_e_input_invalid")
    snapshot = value.sealed_snapshot
    gate_d_observations = authorized.request.gate_d_result.observations
    if len(snapshot.observations) != len(gate_d_observations):
        raise GateEAuthorizationError("gate_e_observation_substituted")
    for relevance_observation, parent_observation in zip(
        snapshot.observations, gate_d_observations, strict=True
    ):
        if (
            relevance_observation.observation_id != parent_observation.external_id
            or relevance_observation.source.source_id != parent_observation.source_id
            or relevance_observation.source.board_key != parent_observation.source_key
            or relevance_observation.title != parent_observation.title
            or relevance_observation.location != (parent_observation.location or "")
            or relevance_observation.description != (parent_observation.description or "")
        ):
            raise GateEAuthorizationError("gate_e_observation_substituted")
    if any(
        not isinstance(observation.canonical_observation_bytes, bytes)
        or not observation.canonical_observation_bytes
        for observation in snapshot.observations
    ):
        raise GateEAuthorizationError("gate_e_observation_invalid")
    if (
        snapshot.source_plan_sha256
        != authorized.request.post_c_request.source_plan.source_plan_sha256
    ):
        raise GateEAuthorizationError("gate_e_source_plan_mismatch")
    if snapshot.namespace != authorized.request.post_c_request.provenance.namespace:
        raise GateEAuthorizationError("gate_e_namespace_mismatch")
    return replace(value)


__all__ = ["adapt_gate_e_input"]
