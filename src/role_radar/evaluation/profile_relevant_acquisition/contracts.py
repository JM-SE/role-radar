"""Immutable operational DTOs for the offline F10.1F transition seam.

The older F10.1E DTOs are re-exported for compatibility with the already
implemented pure preview/materialization boundary.  The operational values in
this module are deliberately tagged and are not coercible into those DTOs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from role_radar.evaluation.profile_relevance.contracts import (
    AcquisitionObservation,
    ApprovedPreview,
    CanonicalPayload,
    ConstraintPolicy,
    FrozenProfile,
    GateDecision,
    HistoricalIdentityExclusion,
    MaterializationContext,
    MaterializedPayloads,
    PartitionPolicy,
    PartitionQuota,
    PartitionResult,
    PreviewComputationResult,
    ProfileRelevanceInput,
    ProjectedFacts,
    QuotaCell,
    RelevancePolicy,
    SamplingMicrocell,
    SamplingPolicy,
    SanitizedPreview,
    SealedAcquisitionSnapshot,
    SelectedItem,
    SelectionResult,
    SourceIdentity,
)

# Re-export the accepted pure dependency.  This is the only compatibility
# surface between the two domains; no operational DTO is a structural alias of
# an F10.1E acknowledgement or materialization context.


HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class OperationalContractError(ValueError):
    """Stable, detail-free error for malformed operational DTOs."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ArtifactClass(StrEnum):
    """Mechanical provenance class; classes are never promoted by shape."""

    SYNTHETIC = "synthetic"
    LIVE_SHAPED = "live_shaped"
    APPROVED_PRODUCTION = "approved_production"


ArtifactOrigin = ArtifactClass
GateName = Literal["preflight", "C", "post-C", "D", "E", "F"]
PrerequisiteStatus = Literal["passed", "failed", "stale", "pending"]


def _nonempty(value: object, code: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise OperationalContractError(code)


def _hash(value: object, code: str) -> None:
    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise OperationalContractError(code)


@dataclass(frozen=True, slots=True)
class SeedInputs:
    """The only acceptable seed input: exactly two distinct 32-byte values."""

    selection_seed: str
    partition_seed: str

    def __post_init__(self) -> None:
        for field in ("selection_seed", "partition_seed"):
            value = getattr(self, field)
            if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
                raise OperationalContractError(f"{field}_invalid")
        if self.selection_seed == self.partition_seed:
            raise OperationalContractError("seeds_must_differ")


@dataclass(frozen=True, slots=True)
class QuotaDesign:
    """Explicit source/board totals and their approved per-board cap."""

    per_board_cap: int
    totals: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.per_board_cap, int)
            or isinstance(self.per_board_cap, bool)
            or self.per_board_cap <= 0
            or self.per_board_cap > 100_000
        ):
            raise OperationalContractError("per_board_cap_invalid")
        if not isinstance(self.totals, tuple):
            raise OperationalContractError("quota_totals_invalid")
        names: set[str] = set()
        for name, total in self.totals:
            _nonempty(name, "quota_source_invalid")
            if name in names:
                raise OperationalContractError("quota_source_duplicate")
            names.add(name)
            if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                raise OperationalContractError("quota_total_invalid")
            if total > self.per_board_cap:
                raise OperationalContractError("quota_exceeds_per_board_cap")


@dataclass(frozen=True, slots=True)
class ChallengeArtifact:
    """One gate-specific challenge, already canonically verified by its loader."""

    schema_version: str
    gate: str
    operation_id: str
    lineage_id: str
    prerequisite_status: str
    artifact_class: ArtifactClass
    seed_inputs: SeedInputs
    policy_sha256: str
    payload_sha256: str
    challenge_sha256: str
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if self.schema_version != "f10.1f-challenge-v1":
            raise OperationalContractError("challenge_schema_invalid")
        if self.gate not in {"C", "post-C", "D", "E", "F"}:
            raise OperationalContractError("challenge_gate_invalid")
        _nonempty(self.operation_id, "challenge_operation_invalid")
        _nonempty(self.lineage_id, "challenge_lineage_invalid")
        if self.prerequisite_status != "passed":
            raise OperationalContractError("challenge_prerequisite_invalid")
        if not isinstance(self.artifact_class, ArtifactClass):
            raise OperationalContractError("challenge_artifact_class_invalid")
        _hash(self.policy_sha256, "challenge_policy_invalid")
        _hash(self.payload_sha256, "challenge_payload_invalid")
        _hash(self.challenge_sha256, "challenge_hash_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise OperationalContractError("challenge_bytes_invalid")


@dataclass(frozen=True, slots=True)
class ProvenanceArtifact:
    """Canonical offline provenance; it contains no handles or runtime state."""

    schema_version: str
    operation_id: str
    lineage_id: str
    commit_sha256: str
    window_sha256: str
    namespace_sha256: str
    policy_sha256: str
    artifact_class: ArtifactClass
    seed_inputs: SeedInputs
    provenance_sha256: str
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if self.schema_version != "f10.1f-provenance-v1":
            raise OperationalContractError("provenance_schema_invalid")
        _nonempty(self.operation_id, "provenance_operation_invalid")
        _nonempty(self.lineage_id, "provenance_lineage_invalid")
        for field in (
            "commit_sha256",
            "window_sha256",
            "namespace_sha256",
            "policy_sha256",
            "provenance_sha256",
        ):
            _hash(getattr(self, field), f"provenance_{field.removesuffix('_sha256')}_invalid")
        if not isinstance(self.artifact_class, ArtifactClass):
            raise OperationalContractError("provenance_artifact_class_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise OperationalContractError("provenance_bytes_invalid")


@dataclass(frozen=True, slots=True)
class TransitionPrerequisite:
    """Exact upstream state required by one local runtime."""

    gate: str
    operation_id: str
    lineage_id: str
    status: str
    artifact_class: ArtifactClass
    challenge_sha256: str
    provenance_sha256: str
    policy_sha256: str
    seed_inputs: SeedInputs
    quota_design: QuotaDesign | None = None

    def __post_init__(self) -> None:
        if self.gate not in {"preflight", "C", "post-C", "D", "E", "F"}:
            raise OperationalContractError("prerequisite_gate_invalid")
        _nonempty(self.operation_id, "prerequisite_operation_invalid")
        _nonempty(self.lineage_id, "prerequisite_lineage_invalid")
        if self.status != "passed":
            raise OperationalContractError("prerequisite_not_terminal")
        if not isinstance(self.artifact_class, ArtifactClass):
            raise OperationalContractError("prerequisite_artifact_class_invalid")
        _hash(self.challenge_sha256, "prerequisite_challenge_invalid")
        _hash(self.provenance_sha256, "prerequisite_provenance_invalid")
        _hash(self.policy_sha256, "prerequisite_policy_invalid")


@dataclass(frozen=True, slots=True)
class RuntimeEvidence:
    """Sanitized result returned by a local runtime; ``stopped`` is terminal."""

    gate: str
    operation_id: str
    evidence_sha256: str
    stopped: bool = True
    result: str = "completed"

    def __post_init__(self) -> None:
        _nonempty(self.gate, "runtime_gate_invalid")
        _nonempty(self.operation_id, "runtime_operation_invalid")
        _hash(self.evidence_sha256, "runtime_evidence_invalid")
        if self.result not in {"completed", "blocked"} or not self.stopped:
            raise OperationalContractError("runtime_not_terminal")


@dataclass(frozen=True, slots=True)
class DecisionStatus:
    """Typed projection used to prevent stale decisions becoming executable."""

    status: str
    executable: bool
    reason: str

    def __post_init__(self) -> None:
        if self.status not in {"approved", "stale", "non_executable", "blocked"}:
            raise OperationalContractError("decision_status_invalid")
        _nonempty(self.reason, "decision_reason_invalid")
        if self.status != "approved" and self.executable:
            raise OperationalContractError("decision_executable_status_invalid")


_SYNTHETIC_MARKER = object()


class SyntheticTestAdapter:
    """An explicit, non-production execution adapter for offline tests."""

    __slots__ = ()

    def __init__(self, marker: object = _SYNTHETIC_MARKER) -> None:
        if marker is not _SYNTHETIC_MARKER:
            raise OperationalContractError("synthetic_adapter_invalid")


def synthetic_test_adapter() -> SyntheticTestAdapter:
    return SyntheticTestAdapter()


@dataclass(frozen=True, slots=True)
class ExternalApprovalBinding:
    """Opaque external approval record required for production execution."""

    artifact_sha256: str
    approval_binding_sha256: str
    issuer: str
    opaque_token: bytes

    def __post_init__(self) -> None:
        for value in (self.artifact_sha256, self.approval_binding_sha256):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise OperationalContractError("approval_hash_invalid")
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise OperationalContractError("approval_issuer_invalid")
        if not isinstance(self.opaque_token, bytes) or len(self.opaque_token) < 16:
            raise OperationalContractError("approval_token_invalid")


ApprovedProductionAuthorization = ExternalApprovalBinding


class AuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require_execution_boundary(
    *,
    artifact_sha256: str,
    test_only_adapter: SyntheticTestAdapter | None,
    approval: ExternalApprovalBinding | None,
    code: str,
) -> None:
    """Require either an explicit offline adapter or a matching approval."""

    if test_only_adapter is not None:
        if not isinstance(test_only_adapter, SyntheticTestAdapter) or approval is not None:
            raise AuthorizationError(code)
        return
    if (
        not isinstance(approval, ExternalApprovalBinding)
        or approval.artifact_sha256 != artifact_sha256
    ):
        raise AuthorizationError(code)


__all__ = [
    "AcquisitionObservation",
    "ApprovedPreview",
    "ApprovedProductionAuthorization",
    "ArtifactClass",
    "ArtifactOrigin",
    "AuthorizationError",
    "CanonicalPayload",
    "ChallengeArtifact",
    "ConstraintPolicy",
    "DecisionStatus",
    "ExternalApprovalBinding",
    "FrozenProfile",
    "GateDecision",
    "HistoricalIdentityExclusion",
    "MaterializationContext",
    "MaterializedPayloads",
    "OperationalContractError",
    "PartitionPolicy",
    "PartitionQuota",
    "PartitionResult",
    "PreviewComputationResult",
    "ProfileRelevanceInput",
    "ProjectedFacts",
    "ProvenanceArtifact",
    "QuotaCell",
    "QuotaDesign",
    "RelevancePolicy",
    "RuntimeEvidence",
    "SamplingMicrocell",
    "SamplingPolicy",
    "SanitizedPreview",
    "SealedAcquisitionSnapshot",
    "SeedInputs",
    "SelectedItem",
    "SelectionResult",
    "SourceIdentity",
    "SyntheticTestAdapter",
    "TransitionPrerequisite",
    "require_execution_boundary",
    "synthetic_test_adapter",
]
