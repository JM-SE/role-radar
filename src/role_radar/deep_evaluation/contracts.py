"""Frozen DTOs crossing the F6 boundaries; no ORM objects are accepted here."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class EvidenceReferenceV1:
    source: Literal["extraction", "preliminary_signal", "ambiguity"]
    reference: str
    excerpt: str


@dataclass(frozen=True, slots=True)
class ResolvableAmbiguityV1:
    code: str
    field: str
    question: str
    evidence: tuple[EvidenceReferenceV1, ...]

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("resolvable ambiguity requires evidence")
        if len(self.question) > 240:
            raise ValueError("ambiguity question exceeds 240 characters")


@dataclass(frozen=True, slots=True)
class DeepEvaluationCandidateV1:
    job_id: str
    job_score_id: str
    profile_id: str
    extraction_id: str | None
    title: str
    company: str
    normalized_location: str | None
    first_seen_at: datetime
    preliminary_score: int
    eligible: bool
    blockers: tuple[dict[str, Any], ...]
    signals: tuple[dict[str, Any], ...]
    ambiguities: tuple[dict[str, Any], ...]
    resolvable_ambiguities: tuple[ResolvableAmbiguityV1, ...]
    ambiguity_resolution_version: str
    extraction: dict[str, Any] | None = None
    profile: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class DeepSelectionV1:
    candidate: DeepEvaluationCandidateV1
    rank: int
    reason: Literal["high_score", "ambiguous_band"]


@dataclass(frozen=True, slots=True)
class DeepEvaluationResultV1:
    fit_score: int
    decision: str
    strengths: tuple[dict[str, Any], ...]
    gaps: tuple[dict[str, Any], ...]
    model_concerns: tuple[dict[str, Any], ...]
    uncertainties: tuple[dict[str, Any], ...]
    recommended_action: str
    confidence: float
