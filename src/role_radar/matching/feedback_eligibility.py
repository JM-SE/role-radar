"""Pure, fail-closed feedback eligibility contract."""

from __future__ import annotations

import hashlib
import json
import re

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import (
    Ambiguity,
    FeedbackEligibilityDecision,
    JobFacts,
    ProfileBinding,
)
from role_radar.matching.policy import canonical_region

POLICY_VERSION = "feedback-remote-eligibility-v1"
_HASH = re.compile(r"^[0-9a-f]{64}$")


def validate_feedback_eligibility(
    value: object, *, profile_binding: dict[str, object] | None = None
) -> bool:
    """Validate checkpoint metadata without re-evaluating or mutating facts."""
    if not isinstance(value, dict):
        return False
    decision = value
    if decision.get("policy_version") != POLICY_VERSION:
        return False
    if profile_binding is not None and decision.get("profile_binding") != profile_binding:
        return False
    if not isinstance(decision.get("profile_binding"), dict):
        return False
    if not isinstance(decision.get("input_sha256"), str) or not _HASH.fullmatch(
        decision["input_sha256"]
    ):
        return False
    eligible = decision.get("eligible")
    reasons = decision.get("reason_codes")
    if not isinstance(eligible, bool) or not isinstance(reasons, list) or not reasons:
        return False
    if not all(isinstance(reason, str) and reason for reason in reasons):
        return False
    if eligible and reasons not in (["worldwide"], ["exact_region_match"]):
        return False
    if eligible and not isinstance(decision.get("extraction_id"), str):
        return False
    return not (not eligible and decision.get("extraction_id") is not None)


def serialize_feedback_eligibility(decision: FeedbackEligibilityDecision) -> dict[str, object]:
    return {
        "policy_version": decision.policy_version,
        "profile_binding": decision.profile_binding.canonical_dict(),
        "input_sha256": decision.input_sha256,
        "eligible": decision.eligible,
        "reason_codes": list(decision.reason_codes),
        "extraction_id": decision.extraction_id,
    }


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def evaluate_feedback_eligibility(
    profile: CandidateProfileV1,
    facts: JobFacts,
    ambiguities: tuple[Ambiguity, ...],
    profile_binding: ProfileBinding,
) -> FeedbackEligibilityDecision:
    """Return one deterministic decision without mutating profile or matching data."""
    relevant = {(item.field, item.code) for item in ambiguities}
    reasons: list[str] = []
    if facts.extraction_id is None:
        reasons.append("extraction_incomplete")
    if any(field == "remote_policy" for field, _ in relevant):
        reasons.append("remote_policy_conflict")
    if facts.remote_policy not in {"remote", "hybrid", "onsite"}:
        reasons.append("remote_policy_unknown")
    else:
        allowed = set(profile.hard_constraints.allowed_remote_policies)
        if allowed and facts.remote_policy not in allowed:
            reasons.append("remote_policy_not_allowed")
        if profile.remote_only and facts.remote_policy in {"hybrid", "onsite"}:
            reasons.append("remote_only_incompatible")
    if any(field == "regions" for field, _ in relevant):
        reasons.append("region_conflict")
    profile_regions = {canonical_region(region) for region in profile.regions}
    if not profile_regions:
        reasons.append("profile_region_unknown")
    if "worldwide" in facts.regions and facts.regions_provenance in {"ats", "extraction"}:
        if not reasons:
            reasons.append("worldwide")
    elif not facts.regions:
        reasons.append("region_unknown")
    elif not profile_regions.intersection(facts.regions):
        reasons.append("region_incompatible")
    elif not reasons:
        reasons.append("exact_region_match")

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
    eligible = not reasons or reasons == ["worldwide"] or reasons == ["exact_region_match"]
    return FeedbackEligibilityDecision(
        policy_version=POLICY_VERSION,
        profile_binding=profile_binding,
        input_sha256=input_sha256,
        eligible=eligible,
        reason_codes=tuple(reasons),
        extraction_id=facts.extraction_id if eligible else None,
    )
