"""Offline-only Gate C local runtime.

The injected callable is a test fake.  This module intentionally has no
provider, transport, persistence, or successor-runtime import.
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


class GateCError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def run_gate_c_runtime(
    *,
    challenge: ChallengeArtifact,
    provenance: ProvenanceArtifact,
    delegate: Callable[[], object],
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
    expected_challenge_sha256: str | None = None,
    expected_provenance_sha256: str | None = None,
) -> RuntimeEvidence:
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "C":
        raise GateCError("gate_c_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateCError("gate_c_provenance_invalid")
    try:
        validate_challenge_artifact(challenge)
        validate_provenance_artifact(provenance)
    except ValueError as exc:
        raise GateCError(getattr(exc, "code", "gate_c_artifact_invalid")) from exc
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
        or test_only_adapter is None
    ):
        raise GateCError("gate_c_artifact_class_boundary")
    if challenge.artifact_class is not provenance.artifact_class:
        raise GateCError("gate_c_artifact_class_mismatch")
    if test_only_adapter is not None and challenge.artifact_class is not ArtifactClass.SYNTHETIC:
        raise GateCError("gate_c_artifact_class_not_synthetic")
    try:
        require_execution_boundary(
            artifact_sha256=challenge.challenge_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="gate_c_execution_authorization_required",
        )
    except ValueError as exc:
        raise GateCError(getattr(exc, "code", "gate_c_execution_authorization_required")) from exc
    if (challenge.operation_id, challenge.lineage_id) != (
        provenance.operation_id,
        provenance.lineage_id,
    ):
        raise GateCError("gate_c_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise GateCError("gate_c_policy_mismatch")
    if challenge.seed_inputs != provenance.seed_inputs:
        raise GateCError("gate_c_seed_mismatch")
    if expected_challenge_sha256 is not None and challenge.challenge_sha256 != (
        expected_challenge_sha256
    ):
        raise GateCError("gate_c_stale_challenge")
    if expected_provenance_sha256 is not None and provenance.provenance_sha256 != (
        expected_provenance_sha256
    ):
        raise GateCError("gate_c_stale_provenance")
    if not callable(delegate):
        raise GateCError("gate_c_delegate_invalid")
    if any(hasattr(delegate, name) for name in ("handle_async_request", "connect", "execute")):
        raise GateCError("gate_c_production_dependency_forbidden")
    try:
        delegate()
    except Exception as exc:
        raise GateCError("gate_c_delegate_failed") from exc
    evidence = hashlib.sha256(
        f"C\0{challenge.challenge_sha256}\0{provenance.provenance_sha256}".encode("ascii")
    ).hexdigest()
    return RuntimeEvidence("C", challenge.operation_id, evidence)


__all__ = ["GateCError", "run_gate_c_runtime"]
