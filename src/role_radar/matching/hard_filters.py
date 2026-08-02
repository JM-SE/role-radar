"""The six independent, conservative D30 blockers."""

from __future__ import annotations

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import HardBlocker, JobFacts
from role_radar.matching.policy import canonical_region, canonical_role, key


def excluded_role(profile: CandidateProfileV1, facts: JobFacts) -> HardBlocker | None:
    title = canonical_role(facts.title) if facts.title else None
    excluded = {canonical_role(value) for value in profile.excluded_roles}
    if title and title in excluded:
        return HardBlocker("excluded_role", "title", (title,), (facts.title_provenance,))
    return None


def onsite_incompatible_remote_only(
    profile: CandidateProfileV1, facts: JobFacts
) -> HardBlocker | None:
    if profile.remote_only and facts.remote_policy in {"onsite", "hybrid"}:
        return HardBlocker(
            "onsite_incompatible_remote_only",
            "remote_policy",
            (facts.remote_policy,),
            (facts.remote_provenance,),
        )
    return None


def region_incompatible(profile: CandidateProfileV1, facts: JobFacts) -> HardBlocker | None:
    if not facts.regions or not profile.regions or "worldwide" in facts.regions:
        return None
    candidate = {canonical_region(value) for value in profile.regions}
    if not candidate.intersection(facts.regions):
        return HardBlocker(
            "region_incompatible", "regions", facts.regions, (facts.regions_provenance,)
        )
    return None


def work_authorization_unavailable(
    profile: CandidateProfileV1, facts: JobFacts
) -> HardBlocker | None:
    if not facts.authorization_required and not facts.no_sponsorship:
        return None
    required = set(facts.work_authorizations)
    constraints = profile.hard_constraints
    unavailable = set(constraints.unavailable_work_authorizations)
    available = set(constraints.available_work_authorizations)
    if required and (
        required & unavailable or (available and not required.intersection(available))
    ):
        return HardBlocker(
            "work_authorization_unavailable",
            "work_authorization",
            tuple(sorted(required)),
            (facts.authorization_provenance,),
        )
    return None


def excluded_required_technology(
    profile: CandidateProfileV1, facts: JobFacts
) -> HardBlocker | None:
    excluded = {key(value) for value in profile.excluded_technologies}
    required = {key(value) for value in facts.required_skills}
    match = tuple(sorted(required & excluded))
    if match:
        return HardBlocker(
            "excluded_required_technology",
            "required_skills",
            match,
            (facts.required_skills_provenance,),
        )
    return None


def employment_hard_constraint(profile: CandidateProfileV1, facts: JobFacts) -> HardBlocker | None:
    allowed = set(profile.hard_constraints.allowed_employment_types)
    if facts.employment_type and allowed and facts.employment_type not in allowed:
        return HardBlocker(
            "employment_hard_constraint",
            "employment_type",
            (facts.employment_type,),
            (facts.employment_provenance,),
        )
    return None


def evaluate_hard_filters(profile: CandidateProfileV1, facts: JobFacts) -> tuple[HardBlocker, ...]:
    checks = (
        excluded_role,
        onsite_incompatible_remote_only,
        region_incompatible,
        work_authorization_unavailable,
        excluded_required_technology,
        employment_hard_constraint,
    )
    return tuple(blocker for check in checks if (blocker := check(profile, facts)) is not None)
