"""Pure profile-first admission policy for transient collector results."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from role_radar.domain.dto import NormalizedJob
from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import (
    JobFacts,
    ProfileBinding,
    ProfileIntakeDecision,
)
from role_radar.matching.hard_filters import evaluate_hard_filters
from role_radar.matching.policy import (
    ScoringPolicyV1,
    canonical_region,
    canonical_remote,
    region_includes,
)
from role_radar.matching.signals import role_match
from role_radar.matching.transient_clarification import TransientDescriptionEvidence
from role_radar.notifications.url_policy import canonical_application_url

POLICY_VERSION = "profile-intake-v2"
_REASON_ORDER = (
    "application_url_missing_or_invalid",
    "role_unknown",
    "role_mismatch",
    "remote_policy_conflict",
    "remote_policy_unknown",
    "remote_policy_not_allowed",
    "remote_only_incompatible",
    "profile_region_unknown",
    "region_conflict",
    "region_unknown",
    "region_incompatible",
    "excluded_role",
    "onsite_incompatible_remote_only",
    "work_authorization_unavailable",
    "excluded_required_technology",
    "employment_hard_constraint",
    "employment_incompatible",
    "authorization_incompatible",
    "authorization_unknown",
    "exact_region_match",
    "worldwide",
    "description_evidence_conflict",
)
_LOCATION_MODES = (
    ("remote", "remote"),
    ("hybrid", "hybrid"),
    ("onsite", "onsite"),
    ("on site", "onsite"),
    ("on-site", "onsite"),
)
_LOCATION_REGIONS = (
    "worldwide",
    "global",
    "latin america",
    "latam",
    "argentina",
    "europe",
    "spain",
    "united states",
)
_REMOTE_POLICIES = ("remote", "hybrid", "onsite")

__all__ = ["POLICY_VERSION", "evaluate_profile_intake"]


def _collector_field(data: Mapping[str, object], name: str) -> Any | None:
    value = data.get(name)
    if value in (None, "", (), [], {}):
        return None
    return value


def _strings(value: Any | None) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str) and item.strip())
    return ()


def _location_evidence(location: str | None) -> tuple[str | None, tuple[str, ...]]:
    if not location:
        return None, ()
    normalized = location.casefold().replace("-", " ")
    modes = {mode for marker, mode in _LOCATION_MODES if marker in normalized}
    regions = {canonical_region(region) for region in _LOCATION_REGIONS if region in normalized}
    if "global" in regions:
        regions.discard("global")
        regions.add("worldwide")
    remote = next(iter(modes)) if len(modes) == 1 else None
    return remote, tuple(sorted(regions))


def evaluate_profile_intake(
    profile: CandidateProfileV1,
    normalized: NormalizedJob,
    *,
    source_type: str,
    source_configuration: Mapping[str, object],
    profile_binding: ProfileBinding,
    clarification: TransientDescriptionEvidence | None = None,
) -> ProfileIntakeDecision:
    """Admit only source evidence sufficient for profile-compatible persistence."""
    codes: set[str] = set()
    application_url = canonical_application_url(normalized.application_url or normalized.source_url)
    if application_url is None:
        codes.add("application_url_missing_or_invalid")

    structured = normalized.structured_data
    explicit_remote = structured.get("remote_policy")
    explicit_regions = _strings(structured.get("regions"))
    location_remote, location_regions = _location_evidence(normalized.location)
    remote_values = {
        canonical_remote(value)
        for value in (explicit_remote, location_remote)
        if isinstance(value, str) and value.strip()
    }
    clarification_remote = (
        canonical_remote(clarification.remote_policy)
        if clarification is not None and clarification.remote_policy is not None
        else None
    )
    ats_remote = canonical_remote(explicit_remote) if isinstance(explicit_remote, str) else None
    location_remote = canonical_remote(location_remote) if location_remote else None
    if source_type == "jobicy" and source_configuration.get("remote_only") is True:
        remote_values.add("remote")
    if clarification_remote is not None and ats_remote is None and location_remote is None:
        remote_values.add(clarification_remote)
    elif clarification_remote is not None and clarification_remote not in remote_values:
        codes.add("remote_policy_conflict")
    if len(remote_values) > 1:
        codes.add("remote_policy_conflict")
    if clarification is not None and clarification.conflict:
        codes.add("description_evidence_conflict")
    remote_policy = next(iter(remote_values)) if len(remote_values) == 1 else None
    if explicit_remote:
        remote_provenance = "ats"
    elif location_remote:
        remote_provenance = "location"
    elif clarification_remote:
        remote_provenance = "transient"
    else:
        remote_provenance = "unknown"
    if remote_policy not in _REMOTE_POLICIES:
        codes.add("remote_policy_unknown")

    regions = {canonical_region(item) for item in explicit_regions if item.strip()}
    explicit_region_set = {canonical_region(item) for item in explicit_regions if item.strip()}
    jobicy_region: str | None = None
    if source_type == "jobicy" and isinstance(source_configuration.get("region"), str):
        asserted = source_configuration["region"]
        if isinstance(asserted, str) and asserted.strip():
            jobicy_region = canonical_region(asserted)
            regions.add(jobicy_region)
    regions_provenance = "ats" if explicit_regions or jobicy_region else "unknown"
    if not regions:
        regions.update(location_regions)
        if location_regions:
            regions_provenance = "location"
    if not explicit_region_set and not location_regions and clarification is not None:
        regions.update(canonical_region(region) for region in clarification.regions)
        if clarification.regions:
            regions_provenance = "transient"
    excluded_regions = {
        canonical_region(region) for region in _strings(structured.get("excluded_regions"))
    }
    if clarification is not None:
        excluded_regions.update(clarification.excluded_regions)
        if clarification.excluded_regions and not structured.get("excluded_regions"):
            excluded_region_provenance = "transient"
        else:
            excluded_region_provenance = "ats"
    else:
        excluded_region_provenance = "ats" if structured.get("excluded_regions") else "unknown"
    # Jobicy's validated job-scope region is authoritative over the provider's
    # free-form location marker when both are present.
    if jobicy_region is not None and jobicy_region in regions:
        regions = {jobicy_region}
    if (
        explicit_region_set
        and location_regions
        and "worldwide" not in regions
        and not any(
            region_includes(left, right) or region_includes(right, left)
            for left in explicit_region_set
            for right in location_regions
        )
    ):
        codes.add("region_conflict")
    if clarification is not None and (clarification.regions or clarification.excluded_regions):
        ats_regions = explicit_region_set or set(location_regions)
        region_conflicts = bool(
            ats_regions
            and clarification.regions
            and not any(
                region_includes(left, right) or region_includes(right, left)
                for left in ats_regions
                for right in clarification.regions
            )
        )
        if region_conflicts:
            codes.add("region_conflict")
    facts = JobFacts(
        title=normalized.title,
        regions=tuple(regions),
        excluded_regions=tuple(excluded_regions),
        remote_policy=remote_policy,
        required_skills=_strings(_collector_field(structured, "required_skills")),
        employment_type=(
            structured["employment_type"]
            if isinstance(structured.get("employment_type"), str)
            else None
        ),
        work_authorizations=_strings(_collector_field(structured, "work_authorizations")),
        authorization_required=bool(_collector_field(structured, "authorization_required")),
        no_sponsorship=bool(_collector_field(structured, "no_sponsorship")),
        title_provenance="ats",
        location_provenance="ats",
        regions_provenance=regions_provenance,
        excluded_regions_provenance=excluded_region_provenance,
        remote_provenance=remote_provenance,
        required_skills_provenance="ats",
        employment_provenance="ats",
        authorization_provenance="ats",
    )
    role, ambiguities = role_match(profile, facts, ScoringPolicyV1().maxima["role_match"])
    if role.points <= 0:
        codes.add("role_unknown" if ambiguities else "role_mismatch")
    if remote_policy in _REMOTE_POLICIES:
        allowed = set(profile.hard_constraints.allowed_remote_policies)
        if allowed and remote_policy not in allowed:
            codes.add("remote_policy_not_allowed")
        if profile.remote_only and remote_policy in {"hybrid", "onsite"}:
            codes.add("remote_only_incompatible")
    codes.update(blocker.code for blocker in evaluate_hard_filters(profile, facts))
    profile_regions = {canonical_region(region) for region in profile.regions}
    profile_locations = profile_regions - {"worldwide"}
    if not profile_regions:
        codes.add("profile_region_unknown")
    elif not facts.regions:
        codes.add("region_unknown")
    elif "worldwide" not in facts.regions and not any(
        region_includes(scope, region)
        for scope in facts.regions
        for region in profile_locations
    ):
        codes.add("region_incompatible")

    ordered = tuple(code for code in _REASON_ORDER if code in codes)
    if not ordered:
        ordered = ("worldwide",) if "worldwide" in regions else ("exact_region_match",)
    evidence = {
        "policy_version": POLICY_VERSION,
        "profile_binding": profile_binding.canonical_dict(),
        "source_type": source_type,
        "source_configuration": dict(source_configuration),
        "normalized": normalized.model_dump(mode="json"),
        "facts": facts.canonical_dict(),
    }
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    eligible = ordered in (("worldwide",), ("exact_region_match",))
    intake_evidence: dict[str, object] = {}
    if remote_policy in _REMOTE_POLICIES:
        intake_evidence["remote_policy"] = remote_policy
    if regions:
        intake_evidence["regions"] = sorted(regions)
    if clarification is not None:
        intake_evidence["description_clarification"] = clarification.canonical_dict()
    if excluded_regions:
        intake_evidence["excluded_regions"] = sorted(excluded_regions)
    return ProfileIntakeDecision(
        policy_version=POLICY_VERSION,
        profile_binding=profile_binding,
        input_sha256=hashlib.sha256(payload).hexdigest(),
        eligible=eligible,
        reason_codes=ordered,
        application_url=application_url if eligible else None,
        intake_evidence=intake_evidence,
    )
