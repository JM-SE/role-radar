"""Mapping v1 from F4 ambiguity facts to concrete, evidence-backed questions."""

from collections.abc import Mapping
from typing import Any

from .contracts import EvidenceReferenceV1, ResolvableAmbiguityV1

AMBIGUITY_RESOLUTION_VERSION = "ambiguity-resolution-v1"
AMBIGUITY_MAPPING_V1: dict[tuple[str, str], tuple[str, str]] = {
    ("remote_policy_unknown", "remote_policy"): (
        "remote_policy",
        "What work arrangement does this role require: remote, hybrid, or onsite?",
    ),
    ("region_unknown", "regions"): (
        "regions",
        "Which regions or countries are eligible for this role?",
    ),
    ("seniority_unknown", "seniority"): (
        "seniority",
        "What seniority level is required for this role?",
    ),
    ("employment_unknown", "employment_type"): (
        "employment_type",
        "What employment type is offered for this role?",
    ),
    ("language_unknown", "languages"): (
        "languages",
        "Which languages and proficiency levels are required?",
    ),
    ("language_level_unknown", "languages"): (
        "languages",
        "What proficiency level is required for each listed language?",
    ),
    ("skills_unknown", "core_skill_match"): (
        "required_skills",
        "Which skills are mandatory for this role?",
    ),
    ("skills_unknown", "secondary_skill_match"): (
        "preferred_skills",
        "Which skills are preferred rather than mandatory for this role?",
    ),
}


def _payload(value: Any) -> tuple[str | None, str | None, Mapping[str, Any] | None]:
    if isinstance(value, Mapping) and "extraction_json" in value:
        return value.get("id"), value.get("validation_status"), value.get("extraction_json")
    if isinstance(value, Mapping):
        return value.get("id"), value.get("validation_status", "valid"), value
    return (
        getattr(value, "id", None),
        getattr(value, "validation_status", None),
        getattr(value, "extraction_json", None),
    )


def _evidence_for_field(
    payload: Mapping[str, Any], field: str, code: str
) -> tuple[EvidenceReferenceV1, ...]:
    value = payload.get(field)
    items = value if isinstance(value, list) else [value]
    refs: list[EvidenceReferenceV1] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            continue
        excerpt = item.get("evidence")
        if not isinstance(excerpt, str) or not excerpt.strip() or len(excerpt) > 240:
            continue
        refs.append(EvidenceReferenceV1("extraction", f"{field}[{index}].evidence", excerpt))
    return tuple(refs[:3])


def resolve_ambiguities_v1(
    ambiguity_json: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    score_extraction_ref: str | None,
    validated_extraction: Any,
) -> tuple[ResolvableAmbiguityV1, ...]:
    """Resolve only known pairs backed by the score's exact valid extraction."""
    extraction_id, status, payload = _payload(validated_extraction)
    normalized_status = getattr(status, "value", status)
    if (
        not score_extraction_ref
        or extraction_id != score_extraction_ref
        or normalized_status != "valid"
        or not payload
    ):
        return ()
    found: list[ResolvableAmbiguityV1] = []
    seen: set[tuple[str, str]] = set()
    for item in ambiguity_json:
        if not isinstance(item, Mapping):
            continue
        raw_code, raw_field = item.get("code"), item.get("field")
        if not isinstance(raw_code, str) or not isinstance(raw_field, str):
            continue
        code, field = raw_code, raw_field
        pair = (code, field)
        mapping = AMBIGUITY_MAPPING_V1.get(pair)
        if mapping is None or pair in seen:
            continue
        mapped_field, question = mapping
        evidence = _evidence_for_field(payload, mapped_field, str(code))
        if not evidence:
            continue
        seen.add(pair)
        found.append(ResolvableAmbiguityV1(str(code), str(field), question, evidence))
    return tuple(found)
