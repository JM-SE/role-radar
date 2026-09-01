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
    ProvenanceArtifact,
    RuntimeEvidence,
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
    offline_harness: bool = False,
    expected_challenge_sha256: str | None = None,
    expected_provenance_sha256: str | None = None,
) -> RuntimeEvidence:
    if not offline_harness:
        raise GateCError("gate_c_offline_harness_required")
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "C":
        raise GateCError("gate_c_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateCError("gate_c_provenance_invalid")
    if challenge.artifact_class is not ArtifactClass.SYNTHETIC:
        raise GateCError("gate_c_artifact_class_not_synthetic")
    if provenance.artifact_class is not ArtifactClass.SYNTHETIC:
        raise GateCError("gate_c_artifact_class_not_synthetic")
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
