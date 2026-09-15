"""Immutable DTOs crossing the boundary into the pure matching core."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from role_radar.matching.policy import (
    canonical_employment,
    canonical_language,
    canonical_region,
    canonical_remote,
    canonical_technology,
)

Provenance = Literal["ats", "extraction", "location", "unknown"]


@dataclass(frozen=True, slots=True)
class ProfileBinding:
    profile_id: str
    row_version: int
    schema_version: int
    canonical_profile_sha256: str

    def canonical_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FeedbackEligibilityDecision:
    policy_version: str
    profile_binding: ProfileBinding
    input_sha256: str
    eligible: bool
    reason_codes: tuple[str, ...]
    extraction_id: str | None


@dataclass(frozen=True, slots=True)
class JobFacts:
    job_id: str = ""
    title: str | None = None
    location: str | None = None
    regions: tuple[str, ...] = ()
    remote_policy: str | None = None
    required_skills: tuple[str, ...] = ()
    preferred_skills: tuple[str, ...] = ()
    seniority: str | None = None
    years_experience: int | None = None
    employment_type: str | None = None
    languages: tuple[tuple[str, str | None], ...] = ()
    work_authorizations: tuple[str, ...] = ()
    authorization_required: bool = False
    no_sponsorship: bool = False
    title_provenance: Provenance = "unknown"
    location_provenance: Provenance = "unknown"
    regions_provenance: Provenance = "unknown"
    remote_provenance: Provenance = "unknown"
    required_skills_provenance: Provenance = "unknown"
    preferred_skills_provenance: Provenance = "unknown"
    seniority_provenance: Provenance = "unknown"
    years_provenance: Provenance = "unknown"
    employment_provenance: Provenance = "unknown"
    languages_provenance: Provenance = "unknown"
    authorization_provenance: Provenance = "unknown"
    extraction_id: str | None = None

    def __post_init__(self) -> None:
        def values(items: tuple[str, ...]) -> tuple[str, ...]:
            return tuple(sorted({canonical_technology(item) for item in items if item.strip()}))

        required = values(self.required_skills)
        preferred = tuple(item for item in values(self.preferred_skills) if item not in required)
        object.__setattr__(self, "title", self.title.strip().casefold() if self.title else None)
        object.__setattr__(
            self, "location", self.location.strip().casefold() if self.location else None
        )
        object.__setattr__(
            self, "regions", tuple(sorted({canonical_region(item) for item in self.regions}))
        )
        if self.remote_policy:
            object.__setattr__(self, "remote_policy", canonical_remote(self.remote_policy))
        if self.employment_type:
            object.__setattr__(self, "employment_type", canonical_employment(self.employment_type))
        object.__setattr__(self, "required_skills", required)
        object.__setattr__(self, "preferred_skills", preferred)
        object.__setattr__(
            self,
            "languages",
            tuple(
                sorted(
                    (canonical_language(language), level.casefold() if level else None)
                    for language, level in self.languages
                    if language.strip()
                )
            ),
        )
        object.__setattr__(self, "work_authorizations", values(self.work_authorizations))

    def canonical_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SignalResult:
    name: str
    points: int
    max_points: int
    reason_codes: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HardBlocker:
    code: str
    field: str
    facts: tuple[str, ...] = ()
    provenance: tuple[Provenance, ...] = ()


@dataclass(frozen=True, slots=True)
class Ambiguity:
    code: str
    field: str
    provenance: Provenance = "unknown"
    detail: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MatchResult:
    scoring_version: str
    policy_version: str
    preliminary_score: int
    eligible: bool
    signals: tuple[SignalResult, ...]
    blockers: tuple[HardBlocker, ...]
    ambiguities: tuple[Ambiguity, ...]
    input_hash: str
    operation_key: str
    extraction_id: str | None = None
