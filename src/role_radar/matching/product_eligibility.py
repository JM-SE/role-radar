"""Pure, fail-closed post-extraction product eligibility policy."""

from __future__ import annotations

import hashlib
import json
import re

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import (
    Ambiguity,
    JobFacts,
    ProductEligibilityDecision,
    ProfileBinding,
)
from role_radar.matching.hard_filters import evaluate_hard_filters
from role_radar.matching.policy import ScoringPolicyV1, canonical_region, region_includes
from role_radar.matching.signals import role_match

POLICY_VERSION = "product-eligibility-v2"
_READABLE_POLICY_VERSIONS = {"product-eligibility-v1", POLICY_VERSION}
_HASH = re.compile(r"^[0-9a-f]{64}$")
_REASON_ORDER = (
    "extraction_incomplete",
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
)


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _ordered(codes: set[str]) -> tuple[str, ...]:
    return tuple(code for code in _REASON_ORDER if code in codes)


def validate_product_eligibility(
    value: object, *, profile_binding: dict[str, object] | None = None
) -> bool:
    """Validate persisted policy evidence without re-evaluating facts."""
    if not isinstance(value, dict) or value.get("policy_version") not in _READABLE_POLICY_VERSIONS:
        return False
    if profile_binding is not None and value.get("profile_binding") != profile_binding:
        return False
    if not isinstance(value.get("profile_binding"), dict):
        return False
    if not isinstance(value.get("input_sha256"), str) or not _HASH.fullmatch(value["input_sha256"]):
        return False
    eligible, reasons = value.get("eligible"), value.get("reason_codes")
    if not isinstance(eligible, bool) or not isinstance(reasons, list) or not reasons:
        return False
    if not all(isinstance(reason, str) and reason for reason in reasons):
        return False
    if eligible and reasons not in (["worldwide"], ["exact_region_match"]):
        return False
    return (
        isinstance(value.get("extraction_id"), str)
        if eligible
        else value.get("extraction_id") is None
    )


def serialize_product_eligibility(decision: ProductEligibilityDecision) -> dict[str, object]:
    return {
        "policy_version": decision.policy_version,
        "profile_binding": decision.profile_binding.canonical_dict(),
        "input_sha256": decision.input_sha256,
        "eligible": decision.eligible,
        "reason_codes": list(decision.reason_codes),
        "extraction_id": decision.extraction_id,
    }


def evaluate_product_eligibility(
    profile: CandidateProfileV1,
    facts: JobFacts,
    ambiguities: tuple[Ambiguity, ...],
    profile_binding: ProfileBinding,
) -> ProductEligibilityDecision:
    """Return the authoritative delivery decision from extracted facts."""
    codes: set[str] = set()
    if facts.extraction_id is None:
        codes.add("extraction_incomplete")

    role, role_ambiguities = role_match(profile, facts, ScoringPolicyV1().maxima["role_match"])
    if role.points <= 0:
        codes.add(
            "role_unknown"
            if any(item.code == "role_unknown" for item in role_ambiguities)
            else "role_mismatch"
        )

    relevant = {(item.field, item.code) for item in ambiguities}
    if any(field == "remote_policy" for field, _ in relevant):
        codes.add("remote_policy_conflict")
    if facts.remote_policy not in {"remote", "hybrid", "onsite"}:
        codes.add("remote_policy_unknown")
    else:
        allowed = set(profile.hard_constraints.allowed_remote_policies)
        if allowed and facts.remote_policy not in allowed:
            codes.add("remote_policy_not_allowed")
        if profile.remote_only and facts.remote_policy in {"hybrid", "onsite"}:
            codes.add("remote_only_incompatible")

    if any(field == "regions" for field, _ in relevant):
        codes.add("region_conflict")
    profile_regions = {canonical_region(region) for region in profile.regions}
    profile_locations = profile_regions - {"worldwide"}
    if not profile_regions:
        codes.add("profile_region_unknown")
    elif "worldwide" in facts.regions and facts.regions_provenance in {
        "ats",
        "extraction",
        "transient",
    }:
        pass
    elif not facts.regions:
        codes.add("region_unknown")
    elif "worldwide" not in facts.regions and not any(
        region_includes(job_scope, profile_region)
        for job_scope in facts.regions
        for profile_region in profile_locations
    ):
        codes.add("region_incompatible")
    elif "worldwide" in facts.regions:
        codes.add("region_unknown")

    codes.update(blocker.code for blocker in evaluate_hard_filters(profile, facts))
    canonical_ambiguities = sorted(
        (item.code, item.field, item.provenance, item.detail) for item in ambiguities
    )
    input_sha256 = hashlib.sha256(
        _json(
            {
                "policy_version": POLICY_VERSION,
                "profile_binding": profile_binding.canonical_dict(),
                "facts": facts.canonical_dict(),
                "ambiguities": canonical_ambiguities,
            }
        )
    ).hexdigest()
    reasons = _ordered(codes)
    if not reasons:
        reasons = ("worldwide",) if "worldwide" in facts.regions else ("exact_region_match",)
    eligible = reasons in (("worldwide",), ("exact_region_match",))
    return ProductEligibilityDecision(
        policy_version=POLICY_VERSION,
        profile_binding=profile_binding,
        input_sha256=input_sha256,
        eligible=eligible,
        reason_codes=reasons,
        extraction_id=facts.extraction_id if eligible else None,
    )
