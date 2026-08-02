"""Versioned aliases and scoring policy; no I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass

SCORING_VERSION = "scoring-v1"
POLICY_VERSION = "policy-v1"

ROLE_ALIASES: dict[str, str] = {
    "backend developer": "backend",
    "backend engineer": "backend",
    "platform engineer": "platform",
    "software engineer": "software",
    "full stack engineer": "full_stack",
    "fullstack engineer": "full_stack",
    "sre": "site_reliability",
    "site reliability engineer": "site_reliability",
}
REGION_ALIASES: dict[str, str] = {"espana": "spain", "es": "spain", "eu": "europe"}
REMOTE_ALIASES: dict[str, str] = {
    "remote": "remote",
    "fully remote": "remote",
    "remote only": "remote",
    "onsite": "onsite",
    "on-site": "onsite",
    "office": "onsite",
    "hybrid": "hybrid",
}
EMPLOYMENT_ALIASES: dict[str, str] = {
    "full-time": "full_time",
    "full time": "full_time",
    "permanent": "full_time",
    "part-time": "part_time",
    "part time": "part_time",
    "contract": "contractor",
    "intern": "internship",
}
LANGUAGE_ALIASES: dict[str, str] = {"en": "english", "es": "spanish", "fr": "french"}
TECHNOLOGY_ALIASES: dict[str, str] = {
    "py": "python", "postgresql": "postgres", "postgres": "postgres",
    "k8s": "kubernetes",
}
LEVEL_ORDER = {
    "unknown": 0,
    "basic": 1,
    "intermediate": 2,
    "advanced": 3,
    "professional": 4,
    "native": 5,
}
SENIORITY_ORDER = {"intern": 0, "junior": 1, "mid": 2, "senior": 3, "staff": 4, "principal": 5}


def key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def canonical_role(value: str) -> str:
    return ROLE_ALIASES.get(key(value), key(value))


def canonical_region(value: str) -> str:
    return REGION_ALIASES.get(key(value), key(value))


def canonical_remote(value: str) -> str:
    return REMOTE_ALIASES.get(key(value), key(value))


def canonical_employment(value: str) -> str:
    return EMPLOYMENT_ALIASES.get(key(value), key(value))


def canonical_language(value: str) -> str:
    return LANGUAGE_ALIASES.get(key(value), key(value))


def canonical_technology(value: str) -> str:
    return TECHNOLOGY_ALIASES.get(key(value), key(value))


def canonical_level(value: str) -> str:
    return key(value).replace(" ", "_")


@dataclass(frozen=True, slots=True)
class ScoringPolicyV1:
    role_match: int = 20
    location_match: int = 20
    core_skill_match: int = 25
    secondary_skill_match: int = 10
    seniority_match: int = 10
    employment_match: int = 10
    language_match: int = 5

    def __post_init__(self) -> None:
        values = self.maxima
        if any(value < 0 for value in values.values()) or sum(values.values()) != 100:
            raise ValueError("ScoringPolicyV1 maxima must be non-negative and sum to 100")

    @property
    def maxima(self) -> dict[str, int]:
        return {
            "role_match": self.role_match,
            "location_match": self.location_match,
            "core_skill_match": self.core_skill_match,
            "secondary_skill_match": self.secondary_skill_match,
            "seniority_match": self.seniority_match,
            "employment_match": self.employment_match,
            "language_match": self.language_match,
        }
