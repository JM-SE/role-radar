"""Temporary, explicit read-only adapter for the F3 profile shape."""

from dataclasses import dataclass
from typing import Any

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import Ambiguity

LEGACY_FIELDS = {
    "roles_target",
    "skills",
    "regions",
    "remote_ok",
    "exclusions",
    "experience_years",
    "languages",
}


@dataclass(frozen=True, slots=True)
class AdaptedProfile:
    profile: CandidateProfileV1
    ambiguities: tuple[Ambiguity, ...]


def adapt_legacy_profile(payload: dict[str, Any]) -> AdaptedProfile:
    """Adapt exactly the known v0 shape; never write the v0 shape back."""
    unknown = set(payload) - LEGACY_FIELDS
    if unknown:
        raise ValueError(f"unsupported legacy profile fields: {', '.join(sorted(unknown))}")
    if set(payload) != LEGACY_FIELDS:
        missing = ", ".join(sorted(LEGACY_FIELDS - set(payload)))
        raise ValueError(f"invalid legacy profile; missing fields: {missing}")

    def string_list(name: str) -> list[str]:
        value = payload[name]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"legacy {name} must be a list of strings")
        return value

    roles = string_list("roles_target")
    skills = string_list("skills")
    regions = string_list("regions")
    exclusions = string_list("exclusions")
    languages_raw = string_list("languages")
    if not isinstance(payload["remote_ok"], bool):
        raise ValueError("legacy remote_ok must be boolean")
    years = payload.get("experience_years")
    if years is not None and (isinstance(years, bool) or not isinstance(years, int) or years < 0):
        raise ValueError("legacy experience_years must be a non-negative integer")
    languages = {language: "unknown" for language in languages_raw}
    ambiguities: list[Ambiguity] = []
    if payload.get("remote_ok") is True:
        ambiguities.append(Ambiguity("legacy_remote_preference", "remote_only", "unknown"))
    if exclusions:
        ambiguities.append(Ambiguity("legacy_exclusions_unclassified", "exclusions", "unknown"))
    profile = CandidateProfileV1.model_validate(
        {
            "title": None,
            "years_of_experience": years,
            "target_roles": [],
        "target_titles": roles,
            "core_skills": [],
        "secondary_skills": skills,
        "regions": regions,
            "remote_only": False,
            "employment_preferences": [],
            "languages": languages,
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {},
            "soft_preferences": {},
        }
    )
    return AdaptedProfile(profile, tuple(ambiguities))
