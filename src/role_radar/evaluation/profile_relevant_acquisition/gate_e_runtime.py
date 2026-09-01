"""Offline Gate E runtime: the sole downstream call is F10.1E compute_preview."""

from __future__ import annotations

from collections.abc import Callable

from role_radar.evaluation.profile_relevance.contracts import (
    PreviewComputationResult,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevance.preview_workflow import compute_preview
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    ProvenanceArtifact,
    SyntheticTestAdapter,
    require_execution_boundary,
    validate_challenge_artifact,
    validate_provenance_artifact,
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
) -> PreviewComputationResult:
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "E":
        raise GateEError("gate_e_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateEError("gate_e_provenance_invalid")
    try:
        validate_challenge_artifact(challenge)
        validate_provenance_artifact(provenance)
    except ValueError as exc:
        raise GateEError(getattr(exc, "code", "gate_e_artifact_invalid")) from exc
    if (
        challenge.artifact_class is ArtifactClass.LIVE_SHAPED
        or provenance.artifact_class is ArtifactClass.LIVE_SHAPED
    ):
        raise GateEError("gate_e_artifact_class_not_executable")
    if challenge.artifact_class is not provenance.artifact_class:
        raise GateEError("gate_e_artifact_class_mismatch")
    if (challenge.artifact_class is ArtifactClass.SYNTHETIC and test_only_adapter is None) or (
        challenge.artifact_class is ArtifactClass.APPROVED_PRODUCTION
        and test_only_adapter is not None
    ):
        raise GateEError("gate_e_artifact_class_boundary")
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
    # This pure branch is the only production-artifact execution allowed in
    # R1; it cannot reach acquisition, persistence, or a materializer.
    return compute_preview(inputs)


__all__ = ["GateEError", "run_gate_e_runtime"]
