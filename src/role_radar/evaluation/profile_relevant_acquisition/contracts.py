"""F10.1F contract seam over the approved pure F10.1E DTOs.

Contracts remain owned by ``profile_relevance``.  This module deliberately
re-exports them under the focused acquisition package instead of defining a
second set of structurally similar DTOs.
"""

# Re-export modules intentionally import names for their public surface.
# ruff: noqa: F401

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

__all__ = [name for name in globals() if not name.startswith("_")]
