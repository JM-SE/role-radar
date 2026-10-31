"""Schemas de ofertas (GET /jobs, GET /jobs/{id})."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from role_radar.domain.enums import JobStatus


class JobSourceReferenceResponse(BaseModel):
    """Referencia resumida de una oferta a una fuente."""

    id: str
    source_id: str
    external_id: str | None
    source_url: str | None
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class JobScoreSummary(BaseModel):
    id: str
    profile_id: str
    extraction_id: str | None
    scoring_version: str
    policy_version: str
    score: int
    preliminary_score: int
    eligible: bool
    signals: list[dict[str, object]]
    blockers: list[dict[str, object]]
    ambiguities: list[dict[str, object]]
    created_at: datetime
    effective_score: int
    final_score: int | None = None
    decision: str | None = None
    recommended_action: str | None = None
    confidence: float | None = None
    deep_evaluation: JobDeepEvaluationSummary | None = None


class JobDeepEvaluationSummary(BaseModel):
    id: str
    status: str
    prompt_version: str
    schema_version: str
    selector_policy_version: str
    fit_score: int | None
    decision: str | None
    strengths: list[dict[str, object]]
    gaps: list[dict[str, object]]
    model_concerns: list[dict[str, object]]
    uncertainties: list[dict[str, object]]
    recommended_action: str | None
    confidence: float | None
    adjustment: int | None
    final_score: int | None
    created_at: datetime


class JobResponse(BaseModel):
    """Oferta canónica (lista)."""

    id: str
    title: str
    company: str
    location: str | None
    normalized_location: str | None
    description: str | None
    application_url: str | None
    status: JobStatus
    first_seen_at: datetime
    last_seen_at: datetime
    published_at: datetime | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime
    latest_score: JobScoreSummary | None = None

    model_config = ConfigDict(from_attributes=True)


class JobDetailResponse(JobResponse):
    """Detalle de oferta con sus referencias de fuente."""

    source_references: list[JobSourceReferenceResponse]


class LocationUnconfirmedResponse(BaseModel):
    """Review-only offer with unknown geographic scope; deliberately has no eligibility score."""

    id: str
    title: str
    company: str
    location: str | None
    source_id: str
    external_id: str
    source_url: str | None
    application_url: str
    reason_code: Literal["region_unknown"]
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)
