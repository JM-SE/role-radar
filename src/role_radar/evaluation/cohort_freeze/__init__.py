"""Public, side-effect-free F10.1C Gate-A surface."""

from role_radar.evaluation.cohort_freeze.contracts import (
    BoundedRepositorySnapshot,
    CandidateEvidence,
    CohortStatus,
    CorpusItem,
    CorpusResult,
    DeploymentIdentity,
    FrozenBundle,
    FrozenBundleV2,
    PartitionResult,
    PreviewResult,
    PreviewV2,
    RepositorySnapshot,
    ResolvedBoundaries,
    SelectionResult,
)
from role_radar.evaluation.cohort_freeze.runtime import CohortFreezeRuntime, CohortFreezeRuntimeV2
from role_radar.evaluation.cohort_freeze.selection import build_bounded_corpus, select_candidates

__all__ = [
    "BoundedRepositorySnapshot",
    "CandidateEvidence",
    "CohortFreezeRuntime",
    "CohortFreezeRuntimeV2",
    "CohortStatus",
    "CorpusItem",
    "CorpusResult",
    "DeploymentIdentity",
    "FrozenBundle",
    "FrozenBundleV2",
    "PartitionResult",
    "PreviewResult",
    "PreviewV2",
    "RepositorySnapshot",
    "ResolvedBoundaries",
    "SelectionResult",
    "build_bounded_corpus",
    "select_candidates",
]
