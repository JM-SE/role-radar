"""Seven pure scoring signals."""

from __future__ import annotations

from math import floor

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import Ambiguity, JobFacts, SignalResult
from role_radar.matching.policy import (
    LEVEL_ORDER,
    SENIORITY_ORDER,
    ScoringPolicyV1,
    canonical_language,
    canonical_role,
    key,
)


def _signal(name: str, points: int, maximum: int, reason: str, evidence: str = "") -> SignalResult:
    return SignalResult(
        name, max(0, min(maximum, points)), maximum, (reason,), (evidence,) if evidence else ()
    )


def role_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    if not facts.title or not (profile.target_roles or profile.target_titles):
        return _signal("role_match", 0, maximum, "role_unknown"), (
            Ambiguity("role_unknown", "title", facts.title_provenance),
        )
    title = canonical_role(facts.title)
    targets = {canonical_role(value) for value in profile.target_titles}
    families = {canonical_role(value) for value in profile.target_roles}
    if title in targets or title in families:
        return _signal("role_match", maximum, maximum, "role_exact", title), ()
    title_tokens = tuple(key(facts.title).split())
    if any(tuple(key(target).split()) == title_tokens for target in profile.target_titles):
        return _signal(
            "role_match", floor(maximum * 15 / 20), maximum, "role_title_sequence", facts.title
        ), ()
    return _signal("role_match", 0, maximum, "role_mismatch", facts.title), ()


def location_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    ambiguities: list[Ambiguity] = []
    modality = 0
    if facts.remote_policy is None:
        ambiguities.append(
            Ambiguity("remote_policy_unknown", "remote_policy", facts.remote_provenance)
        )
    elif profile.remote_only and facts.remote_policy == "remote":
        modality = 10
    elif profile.remote_only and facts.remote_policy in {"onsite", "hybrid"}:
        modality = 0
    else:
        modality = 10
    regions = set(facts.regions)
    candidate_regions = {key(value) for value in profile.regions}
    region_points = 0
    if not regions or not candidate_regions:
        ambiguities.append(Ambiguity("region_unknown", "regions", facts.regions_provenance))
    elif "worldwide" in regions or regions.intersection(candidate_regions):
        region_points = 10
    points = floor(maximum * (modality + region_points) / 20)
    return _signal(
        "location_match", points, maximum, "location_accounted", f"{modality}+{region_points}"
    ), tuple(ambiguities)


def _skill_signal(
    name: str, profile_skills: tuple[str, ...], facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    if not profile_skills or not (facts.required_skills or facts.preferred_skills):
        return _signal(name, 0, maximum, "skills_unknown"), (
            Ambiguity("skills_unknown", name, facts.required_skills_provenance),
        )
    required = {key(skill) for skill in facts.required_skills}
    preferred = {key(skill) for skill in facts.preferred_skills} - required
    units = sum(
        2 if key(skill) in required else 1 if key(skill) in preferred else 0
        for skill in profile_skills
    )
    points = floor(maximum * units / (2 * len(set(profile_skills))))
    return _signal(name, points, maximum, "skills_accounted", str(units)), ()


def core_skill_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    return _skill_signal("core_skill_match", profile.core_skills, facts, maximum)


def secondary_skill_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    return _skill_signal("secondary_skill_match", profile.secondary_skills, facts, maximum)


def seniority_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    if profile.years_of_experience is not None and facts.years_experience is not None:
        return _signal(
            "seniority_match",
            maximum if profile.years_of_experience >= facts.years_experience else 0,
            maximum,
            "years_accounted",
        ), ()
    candidate = profile.title.casefold() if profile.title else None
    level = SENIORITY_ORDER.get(facts.seniority or "")
    candidate_level = next(
        (SENIORITY_ORDER[item] for item in SENIORITY_ORDER if candidate and item in candidate), None
    )
    if level is None or candidate_level is None:
        return _signal("seniority_match", 0, maximum, "seniority_unknown"), (
            Ambiguity("seniority_unknown", "seniority", facts.seniority_provenance),
        )
    points = (
        maximum if candidate_level >= level else maximum // 2 if candidate_level == level - 1 else 0
    )
    return _signal("seniority_match", points, maximum, "seniority_accounted"), ()


def employment_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    if not facts.employment_type or not profile.employment_preferences:
        return _signal("employment_match", 0, maximum, "employment_unknown"), (
            Ambiguity("employment_unknown", "employment_type", facts.employment_provenance),
        )
    points = maximum if facts.employment_type in profile.employment_preferences else 0
    return _signal("employment_match", points, maximum, "employment_accounted"), ()


def language_match(
    profile: CandidateProfileV1, facts: JobFacts, maximum: int
) -> tuple[SignalResult, tuple[Ambiguity, ...]]:
    if not profile.languages or not facts.languages:
        return _signal("language_match", 0, maximum, "language_unknown"), (
            Ambiguity("language_unknown", "languages", facts.languages_provenance),
        )
    points = 0
    ambiguous = False
    for language, required_level in facts.languages:
        candidate_level = profile.languages.get(canonical_language(language))
        if candidate_level is None:
            continue
        if required_level is None or required_level == "unknown":
            points += 1
        elif candidate_level == "unknown":
            ambiguous = True
        elif LEVEL_ORDER.get(candidate_level, 0) >= LEVEL_ORDER.get(required_level, 0):
            points += 1
    maximum_required = max(1, len(facts.languages))
    result = _signal(
        "language_match", floor(maximum * points / maximum_required), maximum, "language_accounted"
    )
    return result, (
        (Ambiguity("language_level_unknown", "languages", facts.languages_provenance),)
        if ambiguous
        else ()
    )


def calculate_signals(
    profile: CandidateProfileV1, facts: JobFacts, policy: ScoringPolicyV1
) -> tuple[tuple[SignalResult, ...], tuple[Ambiguity, ...]]:
    functions = (
        ("role_match", role_match),
        ("location_match", location_match),
        ("core_skill_match", core_skill_match),
        ("secondary_skill_match", secondary_skill_match),
        ("seniority_match", seniority_match),
        ("employment_match", employment_match),
        ("language_match", language_match),
    )
    results: list[SignalResult] = []
    ambiguities: list[Ambiguity] = []
    for name, function in functions:
        result, found = function(profile, facts, policy.maxima[name])
        results.append(result)
        ambiguities.extend(found)
    return tuple(results), tuple(ambiguities)
