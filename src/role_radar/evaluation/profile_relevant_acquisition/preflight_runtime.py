"""Offline preflight composition; it validates and then stops."""

from __future__ import annotations

from dataclasses import dataclass

from role_radar.evaluation.profile_relevant_acquisition.challenge_loader import (
    ChallengeLoadError,
    load_challenge_bytes,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ChallengeArtifact,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    ProvenanceArtifact,
)
from role_radar.evaluation.profile_relevant_acquisition.provenance_loader import (
    ProvenanceLoadError,
    load_provenance_bytes,
)


class PreflightError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PreflightEvidence:
    provenance: ProvenanceArtifact
    challenge: ChallengeArtifact | None
    passed: bool = True


def run_preflight(
    *,
    provenance_bytes: bytes,
    challenge_bytes: bytes | None = None,
    expected_gate: str = "C",
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> PreflightEvidence:
    """Load only bounded artifacts and verify their independent bindings.

    The function deliberately accepts bytes rather than paths.  Filesystem
    access belongs to a caller-controlled adapter; this seam has no writes,
    network, database, provider, or next-gate access.
    """

    try:
        provenance = load_provenance_bytes(
            provenance_bytes,
            approval=approval,
            approval_verifier=approval_verifier,
        )
        challenge = (
            None
            if challenge_bytes is None
            else load_challenge_bytes(
                challenge_bytes,
                expected_gate=expected_gate,
                approval=approval,
                approval_verifier=approval_verifier,
            )
        )
    except (ChallengeLoadError, ProvenanceLoadError) as exc:
        raise PreflightError(exc.code) from exc
    if challenge is not None:
        if challenge.operation_id != provenance.operation_id:
            raise PreflightError("preflight_operation_mismatch")
        if challenge.lineage_id != provenance.lineage_id:
            raise PreflightError("preflight_lineage_mismatch")
        if challenge.policy_sha256 != provenance.policy_sha256:
            raise PreflightError("preflight_policy_mismatch")
        if challenge.seed_inputs != provenance.seed_inputs:
            raise PreflightError("preflight_seed_mismatch")
        if challenge.artifact_class != provenance.artifact_class:
            raise PreflightError("preflight_artifact_class_mismatch")
    return PreflightEvidence(provenance=provenance, challenge=challenge)


__all__ = ["PreflightError", "PreflightEvidence", "run_preflight"]
