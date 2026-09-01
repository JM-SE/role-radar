"""Offline-only Gate D local composition over an explicit test fake."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    ProvenanceArtifact,
    RuntimeEvidence,
    SyntheticTestAdapter,
    require_execution_boundary,
    validate_challenge_artifact,
    validate_provenance_artifact,
)


class GateDError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def run_gate_d_runtime(
    *,
    challenge: ChallengeArtifact,
    provenance: ProvenanceArtifact,
    delegate: Callable[[], object],
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> RuntimeEvidence:
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "D":
        raise GateDError("gate_d_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateDError("gate_d_provenance_invalid")
    try:
        validate_challenge_artifact(challenge)
        validate_provenance_artifact(provenance)
    except ValueError as exc:
        raise GateDError(getattr(exc, "code", "gate_d_artifact_invalid")) from exc
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
        or test_only_adapter is None
    ):
        raise GateDError("gate_d_artifact_class_boundary")
    if challenge.artifact_class is not provenance.artifact_class:
        raise GateDError("gate_d_artifact_class_mismatch")
    if test_only_adapter is not None and challenge.artifact_class is not ArtifactClass.SYNTHETIC:
        raise GateDError("gate_d_artifact_class_not_synthetic")
    try:
        require_execution_boundary(
            artifact_sha256=challenge.challenge_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="gate_d_execution_authorization_required",
        )
    except ValueError as exc:
        raise GateDError(getattr(exc, "code", "gate_d_execution_authorization_required")) from exc
    if challenge.operation_id != provenance.operation_id or challenge.lineage_id != (
        provenance.lineage_id
    ):
        raise GateDError("gate_d_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise GateDError("gate_d_policy_mismatch")
    if challenge.seed_inputs != provenance.seed_inputs:
        raise GateDError("gate_d_seed_mismatch")
    if not callable(delegate):
        raise GateDError("gate_d_delegate_invalid")
    if any(hasattr(delegate, name) for name in ("handle_async_request", "connect", "execute")):
        raise GateDError("gate_d_production_dependency_forbidden")
    try:
        delegate()
    except Exception as exc:
        raise GateDError("gate_d_delegate_failed") from exc
    evidence = hashlib.sha256(
        f"D\0{challenge.challenge_sha256}\0{provenance.provenance_sha256}".encode("ascii")
    ).hexdigest()
    return RuntimeEvidence("D", challenge.operation_id, evidence)


__all__ = ["GateDError", "run_gate_d_runtime"]
