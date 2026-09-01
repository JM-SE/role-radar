"""Offline-only Gate D local composition over an explicit test fake."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ProvenanceArtifact,
    RuntimeEvidence,
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
    offline_harness: bool = False,
    expected_challenge_sha256: str | None = None,
    expected_provenance_sha256: str | None = None,
) -> RuntimeEvidence:
    if not offline_harness:
        raise GateDError("gate_d_offline_harness_required")
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "D":
        raise GateDError("gate_d_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateDError("gate_d_provenance_invalid")
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
    ):
        raise GateDError("gate_d_artifact_class_not_synthetic")
    if challenge.operation_id != provenance.operation_id or challenge.lineage_id != (
        provenance.lineage_id
    ):
        raise GateDError("gate_d_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise GateDError("gate_d_policy_mismatch")
    if challenge.seed_inputs != provenance.seed_inputs:
        raise GateDError("gate_d_seed_mismatch")
    if expected_challenge_sha256 is not None and challenge.challenge_sha256 != (
        expected_challenge_sha256
    ):
        raise GateDError("gate_d_stale_challenge")
    if expected_provenance_sha256 is not None and provenance.provenance_sha256 != (
        expected_provenance_sha256
    ):
        raise GateDError("gate_d_stale_provenance")
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
