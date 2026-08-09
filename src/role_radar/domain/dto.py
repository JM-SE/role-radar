"""DTOs del dominio para la adquisición y normalización de ofertas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RawJob(BaseModel):
    """Oferta tal como la entrega un collector de una fuente externa."""

    source: str
    external_id: str
    source_url: str | None = None
    application_url: str | None = None
    title: str
    company: str
    location: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    structured_data: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime


class NormalizedJob(BaseModel):
    """Oferta lista para prefiltro y deduplicación."""

    source: str
    external_id: str
    source_url: str | None = None
    application_url: str | None = None
    title: str
    company: str
    location: str | None = None
    normalized_location: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    description_hash: str | None = None
    structured_data: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime
