"""Strict, PII-free candidate profile contract used by matching."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from role_radar.matching.policy import (
    canonical_employment,
    canonical_language,
    canonical_region,
    canonical_role,
    canonical_technology,
)

EmploymentType = Literal[
    "full_time", "part_time", "contractor", "temporary", "internship", "unknown"
]
LanguageLevel = Literal["native", "professional", "advanced", "intermediate", "basic", "unknown"]


def normalize_text(value: str) -> str:
    """Apply the one canonical text normalization used by profile hashing."""
    result = unicodedata.normalize("NFKC", value)
    result = re.sub(r"\s+", " ", result).strip()
    if not result:
        raise ValueError("strings in a profile cannot be empty")
    return result.casefold()


def _canonical_list(values: list[str] | tuple[str, ...]) -> list[str]:
    return sorted({normalize_text(value) for value in values})


def _canonical_alias_list(
    values: list[str] | tuple[str, ...], canonicalizer: Callable[[str], str]
) -> tuple[str, ...]:
    return tuple(sorted({canonicalizer(value) for value in values}))


class ProfileHardConstraints(BaseModel):
    """Explicit constraints; an empty list means unknown/no hard restriction."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    available_work_authorizations: tuple[str, ...] = ()
    unavailable_work_authorizations: tuple[str, ...] = ()
    allowed_employment_types: tuple[EmploymentType, ...] = ()

    @field_validator(
        "available_work_authorizations", "unavailable_work_authorizations", mode="before"
    )
    @classmethod
    def canonicalize_authorizations(cls, value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_canonical_list(value))

    @field_validator("allowed_employment_types", mode="before")
    @classmethod
    def canonicalize_employment(cls, value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        return tuple(canonical_employment(item) for item in value)


class ProfileSoftPreferences(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    preferred_industries: tuple[str, ...] = ()

    @field_validator("preferred_industries", mode="before")
    @classmethod
    def canonicalize_industries(cls, value: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_canonical_list(value))


class CandidateProfileV1(BaseModel):
    """Canonical profile. Legacy fields are intentionally not accepted here."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    title: str | None = Field(...)
    years_of_experience: StrictInt | None = Field(..., ge=0)
    target_roles: tuple[str, ...] = Field(...)
    target_titles: tuple[str, ...] = Field(...)
    core_skills: tuple[str, ...] = Field(...)
    secondary_skills: tuple[str, ...] = Field(...)
    regions: tuple[str, ...] = Field(...)
    remote_only: StrictBool = Field(...)
    employment_preferences: tuple[EmploymentType, ...] = Field(...)
    languages: dict[str, LanguageLevel] = Field(...)
    excluded_roles: tuple[str, ...] = Field(...)
    excluded_technologies: tuple[str, ...] = Field(...)
    hard_constraints: ProfileHardConstraints = Field(...)
    soft_preferences: ProfileSoftPreferences = Field(...)

    @model_validator(mode="before")
    @classmethod
    def normalize_payload(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        result = dict(value)
        if result.get("title") is not None:
            result["title"] = normalize_text(result["title"])
        for key in (
            "target_titles",
            "core_skills",
            "secondary_skills",
            "regions",
            "excluded_roles",
            "excluded_technologies",
        ):
            if key in result:
                result[key] = tuple(_canonical_list(result[key]))
        if "target_roles" in result:
            result["target_roles"] = _canonical_alias_list(result["target_roles"], canonical_role)
        if "regions" in result:
            result["regions"] = _canonical_alias_list(result["regions"], canonical_region)
        for key in ("core_skills", "secondary_skills", "excluded_technologies"):
            if key in result:
                result[key] = _canonical_alias_list(result[key], canonical_technology)
        if "employment_preferences" in result:
            result["employment_preferences"] = tuple(
                canonical_employment(value) for value in result["employment_preferences"]
            )
        if "languages" in result:
            result["languages"] = {
                canonical_language(language): level
                for language, level in result["languages"].items()
            }
        hard = result.get("hard_constraints")
        if isinstance(hard, dict):
            hard = dict(hard)
            for key in ("available_work_authorizations", "unavailable_work_authorizations"):
                if key in hard:
                    hard[key] = _canonical_list(hard[key])
            if "allowed_employment_types" in hard:
                hard["allowed_employment_types"] = _canonical_list(hard["allowed_employment_types"])
            result["hard_constraints"] = hard
        soft = result.get("soft_preferences")
        if isinstance(soft, dict):
            soft = dict(soft)
            if "preferred_industries" in soft:
                soft["preferred_industries"] = _canonical_list(soft["preferred_industries"])
            result["soft_preferences"] = soft
        # Core wins over secondary, as required by D28.
        if "core_skills" in result and "secondary_skills" in result:
            core = set(result["core_skills"])
            result["secondary_skills"] = tuple(
                skill for skill in result["secondary_skills"] if skill not in core
            )
        return result

    @model_validator(mode="after")
    def validate_language_keys(self) -> CandidateProfileV1:
        if set(self.languages) != {canonical_language(key) for key in self.languages}:
            raise ValueError("language keys must be canonical")
        return self


def canonical_profile_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-compatible canonical v1 payload."""
    return CandidateProfileV1.model_validate(payload).model_dump(mode="json")


def canonical_profile_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize a canonical v1 payload deterministically for evidence hashes."""
    canonical = canonical_profile_payload(payload)
    return json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_profile_sha256(payload: dict[str, Any]) -> str:
    """Return the SHA-256 fingerprint of the canonical v1 payload."""
    return hashlib.sha256(canonical_profile_bytes(payload)).hexdigest()
