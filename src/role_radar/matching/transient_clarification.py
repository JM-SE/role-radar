"""Bounded, deterministic clarification of explicit job-description evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass

from role_radar.matching.policy import canonical_region

POLICY_VERSION = "description-clarification-v1"
MAX_DESCRIPTION_CHARS = 12_000
MAX_ATTEMPTS_PER_RUN = 16

_REMOTE_PATTERNS = {
    "remote": re.compile(
        r"\b(?:fully remote (?:position|role|job)|100% remote (?:position|role|job)|"
        r"remote (?:position|role|job)|work remotely|remote (?:from|in|within|across|worldwide))\b",
        re.IGNORECASE,
    ),
    "hybrid": re.compile(r"\bhybrid (?:position|role|work)\b", re.IGNORECASE),
    "onsite": re.compile(r"\b(?:onsite|on-site|on site) (?:position|role|work)\b", re.IGNORECASE),
}
_NEGATED_OR_CONDITIONAL = re.compile(
    r"\b(?:not|never|may|might|could|occasionally|option(?:al)?|either|depending)\b",
    re.IGNORECASE,
)
_COUNTRY_PATTERNS = {
    "argentina": re.compile(r"\b(?:argentina|argentinian)\b", re.IGNORECASE),
    "united states": re.compile(r"\b(?:united states|u\.s\.|usa)\b", re.IGNORECASE),
    "spain": re.compile(r"\b(?:spain|spanish)\b", re.IGNORECASE),
}
_LATAM = re.compile(r"\b(?:latam|latin america)\b", re.IGNORECASE)
_WORLDWIDE = re.compile(r"\b(?:worldwide|anywhere in the world|globally)\b", re.IGNORECASE)
_EXCLUSION = re.compile(
    r"\b(?:excluding|except(?: for)?|not available in|cannot be based in|must not be based in)\b",
    re.IGNORECASE,
)
_WORK_SCOPE = re.compile(
    r"\b(?:based in|located in|work from|work remotely from|remote from|remote in|"
    r"open to candidates in|remote)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class TransientDescriptionEvidence:
    policy_version: str
    remote_policy: str | None = None
    regions: tuple[str, ...] = ()
    excluded_regions: tuple[str, ...] = ()
    conflict: bool = False

    def canonical_dict(self) -> dict[str, object]:
        return {
            "policy_version": self.policy_version,
            "remote_policy": self.remote_policy,
            "regions": list(self.regions),
            "excluded_regions": list(self.excluded_regions),
            "conflict": self.conflict,
        }


def clarify_description(description: str | None) -> TransientDescriptionEvidence | None:
    """Extract only explicit, unambiguous claims; never infer from incidental prose."""
    if not description:
        return None
    if len(description) > MAX_DESCRIPTION_CHARS:
        return None
    text = description
    sentences = tuple(part.strip() for part in re.split(r"[.!?\n]+", text) if part.strip())
    modalities: set[str] = set()
    for sentence in sentences:
        if _NEGATED_OR_CONDITIONAL.search(sentence):
            continue
        if re.search(r"\bhybrid work required\b", sentence, re.IGNORECASE):
            modalities.add("hybrid")
        for modality, pattern in _REMOTE_PATTERNS.items():
            if pattern.search(sentence):
                modalities.add(modality)

    region_claims: set[str] = set()
    excluded_regions: set[str] = set()
    for sentence in sentences:
        matches: set[str] = set()
        scope = _WORK_SCOPE.search(sentence)
        if scope:
            scoped_text = sentence[scope.end() :]
            excluded_scope = _EXCLUSION.search(sentence)
            if excluded_scope:
                scoped_text = sentence[scope.end() : excluded_scope.start()]
            if _WORLDWIDE.search(scoped_text):
                matches.add("worldwide")
            if _LATAM.search(scoped_text):
                matches.add("latam")
            for region, pattern in _COUNTRY_PATTERNS.items():
                if pattern.search(scoped_text):
                    matches.add(canonical_region(region))
        exclusion = _EXCLUSION.search(sentence)
        if exclusion:
            suffix = sentence[exclusion.end() :]
            excluded_regions.update(
                canonical_region(region)
                for region, pattern in _COUNTRY_PATTERNS.items()
                if pattern.search(suffix)
            )
            if _LATAM.search(suffix):
                excluded_regions.add("latam")
            if not matches and _LATAM.search(sentence):
                matches.add("latam")
            matches.difference_update(excluded_regions)
        region_claims.update(matches)

    # Multiple distinct modality/scope claims are contradictory, not a vote.
    remote_policy = next(iter(modalities)) if len(modalities) == 1 else None
    regions = tuple(sorted(region_claims))
    conflict = len(modalities) > 1 or (
        len(region_claims) > 1
        and not (
            "latam" in region_claims
            and "argentina" in region_claims
            and len(region_claims) == 2
        )
    )
    if remote_policy is None and not regions and not excluded_regions and not conflict:
        return None
    return TransientDescriptionEvidence(
        policy_version=POLICY_VERSION,
        remote_policy=remote_policy,
        regions=regions,
        excluded_regions=tuple(sorted(excluded_regions)),
        conflict=conflict,
    )
