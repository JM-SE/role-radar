"""Immutable operational DTOs for the offline F10.1F transition seam.

The older F10.1E DTOs are re-exported for compatibility with the already
implemented pure preview/materialization boundary.  The operational values in
this module are deliberately tagged and are not coercible into those DTOs.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Literal, Protocol

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
_APPROVED_ARTIFACT_TOKEN = object()


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
    _approval_token: object | None = dataclass_field(
        default=None, repr=False, compare=False, kw_only=True
    )

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
        if not isinstance(self.seed_inputs, SeedInputs):
            raise OperationalContractError("challenge_seed_inputs_invalid")
        _hash(self.policy_sha256, "challenge_policy_invalid")
        _hash(self.payload_sha256, "challenge_payload_invalid")
        _hash(self.challenge_sha256, "challenge_hash_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise OperationalContractError("challenge_bytes_invalid")
        if self.artifact_class is ArtifactClass.APPROVED_PRODUCTION:
            if self._approval_token is not _APPROVED_ARTIFACT_TOKEN:
                raise OperationalContractError("challenge_external_approval_required")
        elif self._approval_token is not None:
            raise OperationalContractError("challenge_approval_token_invalid")
        _validate_canonical_artifact(
            canonical_bytes=self.canonical_bytes,
            supplied_hash=self.challenge_sha256,
            domain="role-radar:f10.1f:challenge:v1",
            hash_key="challenge_sha256",
            expected={
                "schema_version": self.schema_version,
                "gate": self.gate,
                "operation_id": self.operation_id,
                "lineage_id": self.lineage_id,
                "prerequisite_status": self.prerequisite_status,
                "artifact_class": self.artifact_class.value,
                "seed_inputs": {
                    "selection_seed": self.seed_inputs.selection_seed,
                    "partition_seed": self.seed_inputs.partition_seed,
                },
                "policy_sha256": self.policy_sha256,
                "payload_sha256": self.payload_sha256,
            },
            mismatch_code="challenge_hash_mismatch",
        )


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
    _approval_token: object | None = dataclass_field(
        default=None, repr=False, compare=False, kw_only=True
    )

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
        if not isinstance(self.seed_inputs, SeedInputs):
            raise OperationalContractError("provenance_seed_inputs_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise OperationalContractError("provenance_bytes_invalid")
        if self.artifact_class is ArtifactClass.APPROVED_PRODUCTION:
            if self._approval_token is not _APPROVED_ARTIFACT_TOKEN:
                raise OperationalContractError("provenance_external_approval_required")
        elif self._approval_token is not None:
            raise OperationalContractError("provenance_approval_token_invalid")
        _validate_canonical_artifact(
            canonical_bytes=self.canonical_bytes,
            supplied_hash=self.provenance_sha256,
            domain="role-radar:f10.1f:provenance:v1",
            hash_key="provenance_sha256",
            expected={
                "schema_version": self.schema_version,
                "operation_id": self.operation_id,
                "lineage_id": self.lineage_id,
                "commit_sha256": self.commit_sha256,
                "window_sha256": self.window_sha256,
                "namespace_sha256": self.namespace_sha256,
                "policy_sha256": self.policy_sha256,
                "artifact_class": self.artifact_class.value,
                "seed_inputs": {
                    "selection_seed": self.seed_inputs.selection_seed,
                    "partition_seed": self.seed_inputs.partition_seed,
                },
            },
            mismatch_code="provenance_hash_mismatch",
        )


def _validate_canonical_artifact(
    *,
    canonical_bytes: bytes,
    supplied_hash: str,
    domain: str,
    hash_key: str,
    expected: dict[str, object],
    mismatch_code: str,
) -> None:
    """Validate the bytes again at every DTO boundary, not only in loaders."""

    if not canonical_bytes.endswith(b"\n") or canonical_bytes[:-1].count(b"\n") != 0:
        raise OperationalContractError("canonical_record_invalid")
    try:
        payload = json.loads(canonical_bytes[:-1].decode("utf-8"))
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OperationalContractError("canonical_record_invalid") from exc
    if not isinstance(payload, dict) or canonical != canonical_bytes[:-1]:
        raise OperationalContractError("canonical_record_invalid")
    if set(payload) != set(expected) | {hash_key}:
        raise OperationalContractError("canonical_record_invalid")
    if any(payload.get(key) != value for key, value in expected.items()):
        raise OperationalContractError(mismatch_code)
    embedded = payload.get(hash_key)
    unsigned = dict(payload)
    unsigned.pop(hash_key, None)
    unsigned_bytes = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256(domain.encode("ascii") + b"\x00" + unsigned_bytes).hexdigest()
    if embedded != supplied_hash or digest != supplied_hash:
        raise OperationalContractError(mismatch_code)


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
        if not isinstance(self.seed_inputs, SeedInputs):
            raise OperationalContractError("prerequisite_seed_inputs_invalid")
        _hash(self.challenge_sha256, "prerequisite_challenge_invalid")
        _hash(self.provenance_sha256, "prerequisite_provenance_invalid")
        _hash(self.policy_sha256, "prerequisite_policy_invalid")


@dataclass(frozen=True, slots=True)
class SourcePlanBinding:
    """Post-C source-plan binding; the plan itself stays outside this seam."""

    operation_id: str
    lineage_id: str
    policy_sha256: str
    source_plan_sha256: str
    artifact_class: ArtifactClass
    prerequisite_status: str

    def __post_init__(self) -> None:
        _nonempty(self.operation_id, "source_plan_operation_invalid")
        _nonempty(self.lineage_id, "source_plan_lineage_invalid")
        _hash(self.policy_sha256, "source_plan_policy_invalid")
        _hash(self.source_plan_sha256, "source_plan_hash_invalid")
        if not isinstance(self.artifact_class, ArtifactClass):
            raise OperationalContractError("source_plan_artifact_class_invalid")
        if self.prerequisite_status != "passed":
            raise OperationalContractError("source_plan_prerequisite_invalid")


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


class ZeroArgumentEffect(Protocol):
    """Private/test-only effect accepted by the non-authoritative runtimes."""

    def __call__(self) -> object: ...


@dataclass(frozen=True, slots=True)
class F10_1FHandoff:
    """Typed, authenticated Gate F handoff consumed by the freeze authority."""

    operation_id: str
    challenge_sha256: str
    provenance_sha256: str
    artifact_class: ArtifactClass
    evidence: RuntimeEvidence
    payloads: MaterializedPayloads
    preview_input_sha256: str
    materialization_context_sha256: str
    materialization_binding_sha256: str
    private_payloads_sha256: str
    operator_payloads_sha256: str
    pilot_payloads_sha256: str
    holdout_payloads_sha256: str

    def __post_init__(self) -> None:
        _nonempty(self.operation_id, "f_handoff_operation_invalid")
        _hash(self.challenge_sha256, "f_handoff_challenge_invalid")
        _hash(self.provenance_sha256, "f_handoff_provenance_invalid")
        if self.artifact_class not in {
            ArtifactClass.SYNTHETIC,
            ArtifactClass.APPROVED_PRODUCTION,
        }:
            raise OperationalContractError("f_handoff_artifact_class_invalid")
        if not isinstance(self.evidence, RuntimeEvidence) or self.evidence.gate != "F":
            raise OperationalContractError("f_handoff_evidence_invalid")
        if self.evidence.operation_id != self.operation_id:
            raise OperationalContractError("f_handoff_operation_mismatch")
        expected = hashlib.sha256(
            f"F\0{self.challenge_sha256}\0{self.provenance_sha256}".encode("ascii")
        ).hexdigest()
        if self.evidence.evidence_sha256 != expected:
            raise OperationalContractError("f_handoff_evidence_mismatch")
        if not isinstance(self.payloads, MaterializedPayloads):
            raise OperationalContractError("f_handoff_payloads_invalid")
        for name in (
            "preview_input_sha256",
            "materialization_context_sha256",
            "materialization_binding_sha256",
            "private_payloads_sha256",
            "operator_payloads_sha256",
            "pilot_payloads_sha256",
            "holdout_payloads_sha256",
        ):
            _hash(getattr(self, name), "f_handoff_binding_invalid")
        if self.preview_input_sha256 != self.payloads.preview_input_sha256:
            raise OperationalContractError("f_handoff_preview_binding_mismatch")
        if self.materialization_context_sha256 != self.payloads.materialization_context_sha256:
            raise OperationalContractError("f_handoff_materialization_binding_mismatch")
        if self.materialization_binding_sha256 != self.payloads.materialization_binding_sha256:
            raise OperationalContractError("f_handoff_materialization_binding_mismatch")
        if (
            self.private_payloads_sha256,
            self.operator_payloads_sha256,
            self.pilot_payloads_sha256,
            self.holdout_payloads_sha256,
        ) != self.payloads.group_hashes:
            raise OperationalContractError("f_handoff_payload_hash_mismatch")


def build_f_handoff(
    *,
    operation_id: str,
    challenge_sha256: str,
    provenance_sha256: str,
    artifact_class: ArtifactClass,
    payloads: MaterializedPayloads,
) -> F10_1FHandoff:
    """Create the only supported freeze input for Gate F materialized bytes."""

    if artifact_class is ArtifactClass.APPROVED_PRODUCTION:
        raise OperationalContractError("f_handoff_approved_class_builder_forbidden")

    evidence_sha256 = hashlib.sha256(
        f"F\0{challenge_sha256}\0{provenance_sha256}".encode("ascii")
    ).hexdigest()
    return F10_1FHandoff(
        operation_id=operation_id,
        challenge_sha256=challenge_sha256,
        provenance_sha256=provenance_sha256,
        artifact_class=artifact_class,
        evidence=RuntimeEvidence("F", operation_id, evidence_sha256),
        payloads=payloads,
        preview_input_sha256=payloads.preview_input_sha256,
        materialization_context_sha256=payloads.materialization_context_sha256,
        materialization_binding_sha256=payloads.materialization_binding_sha256,
        private_payloads_sha256=payloads.private_payloads_sha256,
        operator_payloads_sha256=payloads.operator_payloads_sha256,
        pilot_payloads_sha256=payloads.pilot_payloads_sha256,
        holdout_payloads_sha256=payloads.holdout_payloads_sha256,
    )


def validate_challenge_artifact(value: object) -> ChallengeArtifact:
    if not isinstance(value, ChallengeArtifact):
        raise OperationalContractError("challenge_contract_invalid")
    try:
        value.__post_init__()
    except OperationalContractError:
        raise
    except (TypeError, ValueError) as exc:
        raise OperationalContractError("challenge_contract_invalid") from exc
    return value


def validate_provenance_artifact(value: object) -> ProvenanceArtifact:
    if not isinstance(value, ProvenanceArtifact):
        raise OperationalContractError("provenance_contract_invalid")
    try:
        value.__post_init__()
    except OperationalContractError:
        raise
    except (TypeError, ValueError) as exc:
        raise OperationalContractError("provenance_contract_invalid") from exc
    return value


def _approved_artifact_token() -> object:
    """Return the loader-only approval capability; not part of the public API."""

    return _APPROVED_ARTIFACT_TOKEN


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


class ExternalApprovalVerifier(Protocol):
    """Injected verifier owned by the external approval system.

    The artifact's embedded class and hashes are assertions only.  Production
    execution requires this out-of-process/externally supplied decision too.
    """

    def verify(self, approval: ExternalApprovalBinding, artifact_sha256: str) -> bool: ...


class AuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require_execution_boundary(
    *,
    artifact_sha256: str,
    test_only_adapter: SyntheticTestAdapter | None,
    approval: ExternalApprovalBinding | None,
    approval_verifier: ExternalApprovalVerifier | None,
    code: str,
) -> None:
    """Require an explicit offline adapter or externally verified approval."""

    if test_only_adapter is not None:
        if not isinstance(test_only_adapter, SyntheticTestAdapter) or approval is not None:
            raise AuthorizationError(code)
        return
    if (
        not isinstance(approval, ExternalApprovalBinding)
        or approval.artifact_sha256 != artifact_sha256
        or approval_verifier is None
    ):
        raise AuthorizationError(code)
    try:
        verify = getattr(approval_verifier, "verify", None)
        valid = verify(approval, artifact_sha256) if callable(verify) else False
    except Exception as exc:
        raise AuthorizationError(code) from exc
    if valid is not True:
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
    "ExternalApprovalVerifier",
    "F10_1FHandoff",
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
    "SourcePlanBinding",
    "SyntheticTestAdapter",
    "TransitionPrerequisite",
    "ZeroArgumentEffect",
    "build_f_handoff",
    "require_execution_boundary",
    "synthetic_test_adapter",
    "validate_challenge_artifact",
    "validate_provenance_artifact",
]
