"""Offline output seam exposing sanitized, typed result contracts only."""

from role_radar.evaluation.profile_relevance.contracts import SanitizedPreview
from role_radar.evaluation.profile_relevant_acquisition.discovery_runtime import (
    BudgetEvidence,
    PrivateRequestEvidence,
    ReportOnlyResult,
)

__all__ = ["BudgetEvidence", "PrivateRequestEvidence", "ReportOnlyResult", "SanitizedPreview"]
