"""Offline Gate E runtime: the sole downstream call is F10.1E compute_preview."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from role_radar.evaluation.profile_relevance.contracts import ProfileRelevanceInput
from role_radar.evaluation.profile_relevance.preview_workflow import compute_preview
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    ProvenanceArtifact,
    SyntheticTestAdapter,
    require_execution_boundary,
)


class GateEError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def run_gate_e_runtime(
    *,
    challenge: ChallengeArtifact,
    provenance: ProvenanceArtifact,
    inputs: ProfileRelevanceInput,
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier
    | Callable[[ExternalApprovalBinding, str], bool]
    | None = None,
    expected_challenge_sha256: str | None = None,
    expected_provenance_sha256: str | None = None,
) -> Any:
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "E":
        raise GateEError("gate_e_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateEError("gate_e_provenance_invalid")
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
    ):
        raise GateEError("gate_e_artifact_class_not_synthetic")
    if challenge.artifact_class is not provenance.artifact_class:
        raise GateEError("gate_e_artifact_class_mismatch")
    try:
        require_execution_boundary(
            artifact_sha256=challenge.challenge_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="gate_e_execution_authorization_required",
        )
    except ValueError as exc:
        raise GateEError(getattr(exc, "code", "gate_e_execution_authorization_required")) from exc
    if challenge.operation_id != provenance.operation_id or challenge.lineage_id != (
        provenance.lineage_id
    ):
        raise GateEError("gate_e_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise GateEError("gate_e_policy_mismatch")
    if challenge.seed_inputs != provenance.seed_inputs:
        raise GateEError("gate_e_seed_mismatch")
    if expected_challenge_sha256 is not None and challenge.challenge_sha256 != (
        expected_challenge_sha256
    ):
        raise GateEError("gate_e_stale_challenge")
    if expected_provenance_sha256 is not None and provenance.provenance_sha256 != (
        expected_provenance_sha256
    ):
        raise GateEError("gate_e_stale_provenance")
    if not isinstance(inputs, ProfileRelevanceInput):
        raise GateEError("gate_e_input_invalid")
    # This is intentionally the only F10.1E call in this module.  In
    # particular, no payload DTO or materializer name is imported here.
    return compute_preview(inputs)


__all__ = ["GateEError", "run_gate_e_runtime"]
