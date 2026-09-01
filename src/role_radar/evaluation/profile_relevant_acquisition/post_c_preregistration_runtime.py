"""Offline-only post-Gate-C preregistration seal seam."""

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
    SeedInputs,
    SourcePlanBinding,
    SyntheticTestAdapter,
    require_execution_boundary,
    validate_challenge_artifact,
    validate_provenance_artifact,
)


class PostCPreregistrationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def run_post_c_preregistration_runtime(
    *,
    challenge: ChallengeArtifact,
    provenance: ProvenanceArtifact,
    seeds: SeedInputs,
    source_plan: SourcePlanBinding,
    delegate: Callable[[], object],
    test_only_adapter: SyntheticTestAdapter | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
    expected_challenge_sha256: str | None = None,
    expected_provenance_sha256: str | None = None,
    expected_source_plan_sha256: str | None = None,
) -> RuntimeEvidence:
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "post-C":
        raise PostCPreregistrationError("post_c_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise PostCPreregistrationError("post_c_provenance_invalid")
    try:
        validate_challenge_artifact(challenge)
        validate_provenance_artifact(provenance)
    except ValueError as exc:
        raise PostCPreregistrationError(getattr(exc, "code", "post_c_artifact_invalid")) from exc
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
        or test_only_adapter is None
    ):
        raise PostCPreregistrationError("post_c_artifact_class_boundary")
    if challenge.artifact_class is not provenance.artifact_class:
        raise PostCPreregistrationError("post_c_artifact_class_mismatch")
    if test_only_adapter is not None and challenge.artifact_class is not ArtifactClass.SYNTHETIC:
        raise PostCPreregistrationError("post_c_artifact_class_not_synthetic")
    try:
        require_execution_boundary(
            artifact_sha256=challenge.challenge_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="post_c_execution_authorization_required",
        )
    except ValueError as exc:
        raise PostCPreregistrationError(
            getattr(exc, "code", "post_c_execution_authorization_required")
        ) from exc
    if challenge.operation_id != provenance.operation_id or challenge.lineage_id != (
        provenance.lineage_id
    ):
        raise PostCPreregistrationError("post_c_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise PostCPreregistrationError("post_c_policy_mismatch")
    if seeds != provenance.seed_inputs or seeds != challenge.seed_inputs:
        raise PostCPreregistrationError("post_c_seed_mismatch")
    if not isinstance(source_plan, SourcePlanBinding):
        raise PostCPreregistrationError("post_c_source_plan_invalid")
    if (
        source_plan.operation_id != challenge.operation_id
        or source_plan.lineage_id != challenge.lineage_id
    ):
        raise PostCPreregistrationError("post_c_source_plan_binding_mismatch")
    if source_plan.policy_sha256 != challenge.policy_sha256:
        raise PostCPreregistrationError("post_c_source_plan_policy_mismatch")
    if source_plan.artifact_class is not challenge.artifact_class:
        raise PostCPreregistrationError("post_c_source_plan_artifact_class_mismatch")
    if (
        expected_source_plan_sha256 is not None
        and source_plan.source_plan_sha256 != expected_source_plan_sha256
    ):
        raise PostCPreregistrationError("post_c_stale_source_plan")
    if expected_challenge_sha256 is not None and challenge.challenge_sha256 != (
        expected_challenge_sha256
    ):
        raise PostCPreregistrationError("post_c_stale_challenge")
    if expected_provenance_sha256 is not None and provenance.provenance_sha256 != (
        expected_provenance_sha256
    ):
        raise PostCPreregistrationError("post_c_stale_provenance")
    if not callable(delegate):
        raise PostCPreregistrationError("post_c_delegate_invalid")
    if any(hasattr(delegate, name) for name in ("handle_async_request", "connect", "execute")):
        raise PostCPreregistrationError("post_c_production_dependency_forbidden")
    try:
        delegate()
    except Exception as exc:
        raise PostCPreregistrationError("post_c_delegate_failed") from exc
    evidence = hashlib.sha256(
        (
            f"post-C\0{challenge.challenge_sha256}\0{provenance.provenance_sha256}"
            f"\0{source_plan.source_plan_sha256}"
        ).encode("ascii")
    ).hexdigest()
    return RuntimeEvidence("post-C", challenge.operation_id, evidence)


__all__ = ["PostCPreregistrationError", "run_post_c_preregistration_runtime"]
