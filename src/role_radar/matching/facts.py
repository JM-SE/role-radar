"""Deterministic assembly of facts from already-loaded snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from role_radar.matching.contracts import Ambiguity, JobFacts, Provenance
from role_radar.matching.policy import (
    canonical_employment,
    canonical_language,
    canonical_region,
    canonical_remote,
)


@dataclass(frozen=True, slots=True)
class SourceReferenceSnapshot:
    id: str
    raw_payload: dict[str, Any] | None = None
    collected_at: str = ""
    authority: int = 0


@dataclass(frozen=True, slots=True)
class ExtractionSnapshot:
    id: str
    input_hash: str
    validation_status: str
    extraction_json: dict[str, Any] | None
    updated_at: str = ""
    created_at: str = ""


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    id: str
    title: str
    location: str | None = None
    description_hash: str | None = None
    source_references: tuple[SourceReferenceSnapshot, ...] = ()
    extractions: tuple[ExtractionSnapshot, ...] = ()


@dataclass(frozen=True, slots=True)
class FactsBuildResult:
    facts: JobFacts
    ambiguities: tuple[Ambiguity, ...]


_ATS_KEYS = {
    "title",
    "location",
    "regions",
    "remote_policy",
    "employment_type",
    "required_skills",
    "preferred_skills",
    "seniority",
    "years_experience",
    "languages",
    "work_authorization",
    "authorization_required",
    "no_sponsorship",
}


def _specified(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != ()


def _extract_value(item: Any) -> Any:
    if isinstance(item, dict) and item.get("state", "specified") != "specified":
        return None
    if isinstance(item, dict) and "value" in item:
        return item["value"]
    return item


def _items(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    values = payload.get(key, [])
    result = []
    for item in values if isinstance(values, list) else []:
        value = item.get("value") if isinstance(item, dict) else item
        if isinstance(value, str) and value.strip():
            result.append(value.strip().casefold())
    return tuple(sorted(set(result)))


def _reference_value(
    references: tuple[SourceReferenceSnapshot, ...], field: str
) -> tuple[Any, Provenance, bool]:
    values: list[tuple[Any, SourceReferenceSnapshot]] = []
    for reference in references:
        payload = reference.raw_payload or {}
        if field in _ATS_KEYS and _specified(payload.get(field)):
            values.append((payload[field], reference))
    if not values:
        return None, "unknown", False
    values.sort(key=lambda pair: pair[1].id)
    values.sort(key=lambda pair: (pair[1].authority, pair[1].collected_at), reverse=True)
    return values[0][0], "ats", len({repr(value) for value, _ in values}) > 1


def build_job_facts(job: JobSnapshot) -> FactsBuildResult:
    """Build facts with ATS precedence and valid, current extraction only."""
    references_list = sorted(job.source_references, key=lambda ref: ref.id)
    references = tuple(
        sorted(references_list, key=lambda ref: (ref.authority, ref.collected_at), reverse=True)
    )
    ambiguities: list[Ambiguity] = []

    def choose(field: str, extraction_value: Any) -> tuple[Any, Provenance]:
        ats_value, provenance, conflict = _reference_value(references, field)
        if conflict:
            ambiguities.append(Ambiguity("ats_value_conflict", field, "ats"))
        if provenance == "ats":
            if _specified(extraction_value) and repr(ats_value) != repr(extraction_value):
                ambiguities.append(Ambiguity("ats_extraction_conflict", field, "ats"))
            return ats_value, "ats"
        if _specified(extraction_value):
            return extraction_value, "extraction"
        return None, "unknown"

    valid = [
        extraction
        for extraction in job.extractions
        if extraction.validation_status == "valid"
        and extraction.input_hash == job.description_hash
        and extraction.extraction_json is not None
    ]
    valid.sort(key=lambda item: item.id)
    valid.sort(key=lambda item: (item.updated_at, item.created_at), reverse=True)
    extraction = valid[0] if valid else None
    if job.extractions and extraction is None:
        ambiguities.append(Ambiguity("stale_or_invalid_extraction", "extraction", "unknown"))
    extraction_payload: dict[str, Any] = (
        extraction.extraction_json if extraction and extraction.extraction_json is not None else {}
    )

    title, title_provenance = choose("title", None)
    if not _specified(title):
        title, title_provenance = job.title, "ats"
    location, location_provenance = choose("location", None)
    if not _specified(location):
        location, location_provenance = job.location, "ats" if job.location else "unknown"
    regions, regions_provenance = choose("regions", _items(extraction_payload, "regions"))
    if not _specified(regions) and location:
        regions = tuple(
            part.strip().casefold()
            for part in str(location).replace("/", ",").split(",")
            if part.strip() and part.strip().casefold() not in {"remote", "worldwide", "global"}
        )
        if regions:
            regions_provenance = location_provenance
    remote, remote_provenance = choose(
        "remote_policy", _extract_value(extraction_payload.get("remote_policy"))
    )
    employment, employment_provenance = choose(
        "employment_type", _extract_value(extraction_payload.get("employment_type"))
    )
    seniority, seniority_provenance = choose(
        "seniority", _extract_value(extraction_payload.get("seniority"))
    )
    years, years_provenance = choose(
        "years_experience", _extract_value(extraction_payload.get("years_experience"))
    )
    required, required_provenance = choose(
        "required_skills", _items(extraction_payload, "required_skills")
    )
    preferred, preferred_provenance = choose(
        "preferred_skills", _items(extraction_payload, "preferred_skills")
    )
    languages_value, languages_provenance = choose(
        "languages", _items(extraction_payload, "languages")
    )
    auth, auth_provenance = choose(
        "work_authorization", _extract_value(extraction_payload.get("work_authorization"))
    )

    def strings(value: Any) -> tuple[str, ...]:
        if isinstance(value, str):
            return (value.casefold(),)
        if isinstance(value, (list, tuple)):
            return tuple(sorted({str(item).casefold() for item in value if str(item).strip()}))
        return ()

    languages: tuple[tuple[str, str | None], ...]
    if isinstance(languages_value, (list, tuple)):
        languages = tuple(sorted((canonical_language(str(item)), None) for item in languages_value))
    elif isinstance(languages_value, dict):
        languages = tuple(
            sorted(
                (canonical_language(str(k)), str(v).casefold()) for k, v in languages_value.items()
            )
        )
    else:
        languages = ()
    facts = JobFacts(
        job_id=job.id,
        title=str(title).casefold() if title else None,
        location=str(location).casefold() if location else None,
        regions=tuple(sorted({canonical_region(value) for value in strings(regions)})),
        remote_policy=canonical_remote(str(remote)) if remote else None,
        required_skills=tuple(sorted(set(strings(required)))),
        preferred_skills=tuple(sorted(set(strings(preferred)) - set(strings(required)))),
        seniority=str(seniority).casefold() if seniority else None,
        years_experience=years if isinstance(years, int) and not isinstance(years, bool) else None,
        employment_type=canonical_employment(str(employment)) if employment else None,
        languages=languages,
        work_authorizations=strings(auth),
        authorization_required=bool(_reference_value(references, "authorization_required")[0]),
        no_sponsorship=bool(_reference_value(references, "no_sponsorship")[0]),
        title_provenance=title_provenance,
        location_provenance=location_provenance,
        regions_provenance=regions_provenance,
        remote_provenance=remote_provenance,
        required_skills_provenance=required_provenance,
        preferred_skills_provenance=preferred_provenance,
        seniority_provenance=seniority_provenance,
        years_provenance=years_provenance,
        employment_provenance=employment_provenance,
        languages_provenance=languages_provenance,
        authorization_provenance=auth_provenance,
        extraction_id=extraction.id if extraction else None,
    )
    return FactsBuildResult(facts, tuple(ambiguities))
