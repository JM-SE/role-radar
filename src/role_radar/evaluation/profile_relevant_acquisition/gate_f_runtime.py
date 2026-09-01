"""Offline-only Gate F materialization seam.

Production roots, capabilities, publication, and the live materialization path
are intentionally unreachable.  The private harness must inject a pure fake
materializer; the callable is invoked exactly once after all guards pass.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ProvenanceArtifact,
    RuntimeEvidence,
)


class GateFError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def run_gate_f_runtime(
    *,
    challenge: ChallengeArtifact,
    provenance: ProvenanceArtifact,
    materializer: Callable[[], Any],
    offline_harness: bool = False,
    expected_challenge_sha256: str | None = None,
    expected_provenance_sha256: str | None = None,
) -> RuntimeEvidence:
    if not offline_harness:
        raise GateFError("gate_f_offline_harness_required")
    if not isinstance(challenge, ChallengeArtifact) or challenge.gate != "F":
        raise GateFError("gate_f_wrong_challenge")
    if not isinstance(provenance, ProvenanceArtifact):
        raise GateFError("gate_f_provenance_invalid")
    if (
        challenge.artifact_class is not ArtifactClass.SYNTHETIC
        or provenance.artifact_class is not ArtifactClass.SYNTHETIC
    ):
        raise GateFError("gate_f_artifact_class_not_synthetic")
    if challenge.operation_id != provenance.operation_id or challenge.lineage_id != (
        provenance.lineage_id
    ):
        raise GateFError("gate_f_lineage_mismatch")
    if challenge.policy_sha256 != provenance.policy_sha256:
        raise GateFError("gate_f_policy_mismatch")
    if challenge.seed_inputs != provenance.seed_inputs:
        raise GateFError("gate_f_seed_mismatch")
    if expected_challenge_sha256 is not None and challenge.challenge_sha256 != (
        expected_challenge_sha256
    ):
        raise GateFError("gate_f_stale_challenge")
    if expected_provenance_sha256 is not None and provenance.provenance_sha256 != (
        expected_provenance_sha256
    ):
        raise GateFError("gate_f_stale_provenance")
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
