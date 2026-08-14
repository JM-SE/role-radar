"""Normalización pura de DTOs RawJob."""

from role_radar.domain.dto import NormalizedJob, RawJob
from role_radar.normalization.text import (
    description_hash,
    html_to_text,
    normalize_company,
    normalize_location,
    normalize_title,
)
from role_radar.normalization.urls import clean_url


def normalize_raw_job(raw: RawJob) -> NormalizedJob:
    """Aplica las transformaciones de URL, texto y hash a una oferta raw."""
    if raw.external_id is None:
        raise ValueError("external_id is required for normalized jobs")
    description = None if raw.description is None else html_to_text(raw.description)
    description = description or None
    location, normalized_location = normalize_location(raw.location)
    return NormalizedJob(
        source=raw.source,
        external_id=raw.external_id,
        source_url=raw.source_url if raw.source == "jobicy" else clean_url(raw.source_url),
        application_url=(
            raw.application_url if raw.source == "jobicy" else clean_url(raw.application_url)
        ),
        title=normalize_title(raw.title),
        company=normalize_company(raw.company),
        location=location,
        normalized_location=normalized_location,
        description=description,
        published_at=raw.published_at,
        description_hash=description_hash(description),
        structured_data=raw.structured_data,
        collected_at=raw.collected_at,
    )
