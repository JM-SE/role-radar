"""Offline-only Gate F materialization seam.

Production roots, capabilities, publication, and the live materialization path
are intentionally unreachable.  The private harness must inject a pure fake
materializer; the callable is invoked exactly once after all guards pass.
"""

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


class GateFError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def run_gate_f_runtime(
    *,
    challenge: ChallengeArtifact,
    provenance: ProvenanceArtifact,
    materializer: Callable[[], object],
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> RuntimeEvidence:
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "F":
        raise GateFError("gate_f_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateFError("gate_f_provenance_invalid")
    try:
        validate_challenge_artifact(challenge)
        validate_provenance_artifact(provenance)
    except ValueError as exc:
        raise GateFError(getattr(exc, "code", "gate_f_artifact_invalid")) from exc
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
        or test_only_adapter is None
    ):
        raise GateFError("gate_f_artifact_class_boundary")
    if challenge.artifact_class is not provenance.artifact_class:
        raise GateFError("gate_f_artifact_class_mismatch")
    if test_only_adapter is not None and challenge.artifact_class is not ArtifactClass.SYNTHETIC:
        raise GateFError("gate_f_artifact_class_not_synthetic")
    try:
        require_execution_boundary(
            artifact_sha256=challenge.challenge_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="gate_f_execution_authorization_required",
        )
    except ValueError as exc:
        raise GateFError(getattr(exc, "code", "gate_f_execution_authorization_required")) from exc
    if challenge.operation_id != provenance.operation_id or challenge.lineage_id != (
        provenance.lineage_id
    ):
        raise GateFError("gate_f_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise GateFError("gate_f_policy_mismatch")
    if challenge.seed_inputs != provenance.seed_inputs:
        raise GateFError("gate_f_seed_mismatch")
    if not callable(materializer):
        raise GateFError("gate_f_materializer_invalid")
    if any(hasattr(materializer, name) for name in ("handle_async_request", "connect", "execute")):
        raise GateFError("gate_f_production_dependency_forbidden")
    try:
        materializer()
    except Exception as exc:
        raise GateFError("gate_f_materializer_failed") from exc
    evidence = hashlib.sha256(
        f"F\0{challenge.challenge_sha256}\0{provenance.provenance_sha256}".encode("ascii")
    ).hexdigest()
    return RuntimeEvidence("F", challenge.operation_id, evidence)


__all__ = ["GateFError", "run_gate_f_runtime"]
