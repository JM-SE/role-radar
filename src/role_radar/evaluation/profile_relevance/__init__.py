"""Public seams for F10.1E profile relevance — side-effect-free."""

from __future__ import annotations

from role_radar.evaluation.profile_relevance.contracts import (
    AcquisitionObservation as AcquisitionObservation,
)
from role_radar.evaluation.profile_relevance.contracts import (
    ApprovedPreview,
    CanonicalPayload,
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
    SanitizedPreview,
    SealedAcquisitionSnapshot,
    SelectedItem,
    SelectionResult,
)
from role_radar.evaluation.profile_relevance.contracts import (
    ConstraintPolicy as ConstraintPolicy,
)
from role_radar.evaluation.profile_relevance.contracts import (
    FrozenProfile as FrozenProfile,
)
from role_radar.evaluation.profile_relevance.contracts import (
    SamplingPolicy as SamplingPolicy,
)
from role_radar.evaluation.profile_relevance.contracts import (
    SourceIdentity as SourceIdentity,
)
from role_radar.evaluation.profile_relevance.errors import ProfileRelevanceError


def compute_preview(inputs: ProfileRelevanceInput) -> PreviewComputationResult:
    """Pure preview seam — validates and returns immutable computation.

    Gate A stub: full orchestration lives in preview_workflow.py once available.
    This stub validates scope/binding and fails closed for live or malformed inputs.
    """
    # Minimal validation to keep stub side-effect-free and deterministic.
    # Full implementation will be provided by preview_workflow.
    try:
        from role_radar.evaluation.profile_relevance.preview_workflow import (
            compute_preview as _impl,
        )

        result: PreviewComputationResult = _impl(inputs)
        return result
    except ImportError as exc:
        # Stub behavior: reject live scope, otherwise raise not-implemented with stable code
        if inputs.relevance_policy.execution_scope != "synthetic_gate_a":
            raise ProfileRelevanceError("offline_scope_required") from exc
        if inputs.sampling_policy.execution_scope != "synthetic_gate_a":
            raise ProfileRelevanceError("offline_scope_required") from exc
        if inputs.partition_policy.execution_scope != "synthetic_gate_a":
            raise ProfileRelevanceError("offline_scope_required") from exc
        raise ProfileRelevanceError("preview_binding_mismatch") from exc


def materialize_payload_bytes(
    approved_preview: ApprovedPreview,
    materialization_context: MaterializationContext,
) -> MaterializedPayloads:
    """Separate pure materialization seam — recomputes preview and returns bytes."""
    try:
        from role_radar.evaluation.profile_relevance.materialization import (
            materialize_payload_bytes as _impl,
        )

        result2: MaterializedPayloads = _impl(approved_preview, materialization_context)
        return result2
    except ImportError as exc:
        # Stub: verify bindings are present, else fail closed before any bytes.
        if not isinstance(approved_preview, ApprovedPreview):
            raise ProfileRelevanceError("approved_preview_required") from exc
        if not isinstance(materialization_context, MaterializationContext):
            raise ProfileRelevanceError("materialization_context_invalid") from exc
        raise ProfileRelevanceError("materialization_context_mismatch") from exc


__all__ = [
    "AcquisitionObservation",
    "ApprovedPreview",
    "CanonicalPayload",
    "ConstraintPolicy",
    "FrozenProfile",
    "GateDecision",
    "HistoricalIdentityExclusion",
    "MaterializationContext",
    "MaterializedPayloads",
    "PartitionPolicy",
    "PartitionQuota",
    "PartitionResult",
    "PreviewComputationResult",
    "ProfileRelevanceError",
    "ProfileRelevanceInput",
    "ProjectedFacts",
    "QuotaCell",
    "RelevancePolicy",
    "SamplingMicrocell",
    "SamplingPolicy",
    "SanitizedPreview",
    "SealedAcquisitionSnapshot",
    "SelectedItem",
    "SelectionResult",
    "SourceIdentity",
    "compute_preview",
    "materialize_payload_bytes",
]
