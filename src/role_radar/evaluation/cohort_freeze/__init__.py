"""Public, side-effect-free F10.1C Gate-A surface."""

from role_radar.evaluation.cohort_freeze.contracts import (
    CandidateEvidence,
    CohortStatus,
    DeploymentIdentity,
    FrozenBundle,
    PreviewResult,
    RepositorySnapshot,
    SelectionResult,
)
from role_radar.evaluation.cohort_freeze.runtime import CohortFreezeRuntime
from role_radar.evaluation.cohort_freeze.selection import select_candidates

__all__ = [
    "CandidateEvidence",
    "CohortFreezeRuntime",
    "CohortStatus",
    "DeploymentIdentity",
    "FrozenBundle",
    "PreviewResult",
    "RepositorySnapshot",
    "SelectionResult",
    "select_candidates",
]
