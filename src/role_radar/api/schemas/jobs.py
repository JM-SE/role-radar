"""Schemas de ofertas (GET /jobs, GET /jobs/{id})."""

from datetime import datetime

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

    model_config = ConfigDict(from_attributes=True)


class JobDetailResponse(JobResponse):
    """Detalle de oferta con sus referencias de fuente."""

    source_references: list[JobSourceReferenceResponse]
