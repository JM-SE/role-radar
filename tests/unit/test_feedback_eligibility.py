from typing import Any, cast

from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256
from role_radar.matching.contracts import Ambiguity, JobFacts, ProfileBinding
from role_radar.matching.product_eligibility import (
    evaluate_product_eligibility as evaluate_feedback_eligibility,
)


def profile(**changes: object) -> CandidateProfileV1:
    payload = {
        "title": "backend engineer",
        "years_of_experience": 8,
        "target_roles": ["backend"],
        "target_titles": ["backend engineer"],
        "core_skills": ["python"],
        "secondary_skills": [],
        "regions": ["eu"],
        "remote_only": True,
        "employment_preferences": ["full_time"],
        "languages": {},
        "excluded_roles": [],
        "excluded_technologies": [],
        "hard_constraints": {},
        "soft_preferences": {},
    }
    payload.update(changes)
    return CandidateProfileV1.model_validate(payload)


def binding(p: CandidateProfileV1) -> ProfileBinding:
    return ProfileBinding("profile-1", 2, 1, canonical_profile_sha256(p.model_dump(mode="json")))


def facts(**changes: object) -> JobFacts:
    values: dict[str, object] = {
        "title": "Backend Engineer",
        "extraction_id": "extraction-1",
        "remote_policy": "remote",
        "regions": ("europe",),
    }
    values.update(changes)
    return JobFacts(**cast(dict[str, Any], values))


def test_exact_worldwide_and_incompatible_regions() -> None:
    p = profile(remote_only=False)
    assert all(
        evaluate_feedback_eligibility(p, facts(remote_policy=policy), (), binding(p)).eligible
        for policy in ("remote", "hybrid", "onsite")
    )
    assert evaluate_feedback_eligibility(p, facts(), (), binding(p)).eligible
    assert evaluate_feedback_eligibility(
        p, facts(regions=("worldwide",), regions_provenance="extraction"), (), binding(p)
    ).reason_codes == ("worldwide",)
    result = evaluate_feedback_eligibility(p, facts(regions=("spain",)), (), binding(p))
    assert not result.eligible and "region_incompatible" in result.reason_codes


def test_remote_constraints_and_unknown_facts_fail_closed() -> None:
    p = profile(hard_constraints={"allowed_remote_policies": ["remote"]})
    assert not evaluate_feedback_eligibility(
        p, facts(remote_policy="mystery"), (), binding(p)
    ).eligible
    assert not evaluate_feedback_eligibility(
        p, facts(remote_policy="hybrid"), (), binding(p)
    ).eligible
    assert not evaluate_feedback_eligibility(
        p, facts(remote_policy="remote", regions=()), (), binding(p)
    ).eligible
    assert not evaluate_feedback_eligibility(
        profile(regions=()), facts(), (), binding(profile(regions=()))
    ).eligible


def test_conflicts_only_relevant_and_free_form_worldwide_is_not_explicit() -> None:
    p = profile()
    conflict = (Ambiguity("ats_value_conflict", "remote_policy", "ats"),)
    assert (
        "remote_policy_conflict"
        in evaluate_feedback_eligibility(p, facts(), conflict, binding(p)).reason_codes
    )
    unrelated = (Ambiguity("signal_conflict", "title", "extraction"),)
    assert evaluate_feedback_eligibility(p, facts(), unrelated, binding(p)).eligible
    location = JobFacts(
        title="Backend Engineer",
        extraction_id="extraction-1",
        remote_policy="remote",
        regions=("worldwide",),
        regions_provenance="location",
    )
    assert not evaluate_feedback_eligibility(p, location, (), binding(p)).eligible


def test_contract_is_ordered_and_hash_is_canonical() -> None:
    p = profile()
    b = binding(p)
    excluded = evaluate_feedback_eligibility(
        p, facts(title=None, extraction_id=None, remote_policy=None, regions=()), (), b
    )
    assert excluded.reason_codes == (
        "extraction_incomplete",
        "role_unknown",
        "remote_policy_unknown",
        "region_unknown",
    )
    assert excluded.extraction_id is None
    assert b.profile_id == "profile-1" and b.row_version == 2 and b.schema_version == 1
    assert evaluate_feedback_eligibility(p, facts(), (), b).extraction_id == "extraction-1"
    first = evaluate_feedback_eligibility(p, facts(regions=("EU",)), (), b)
    second = evaluate_feedback_eligibility(p, facts(regions=("europe",)), (), b)
    assert first.input_sha256 == second.input_sha256
    assert (
        first.input_sha256
        != evaluate_feedback_eligibility(p, facts(remote_policy="hybrid"), (), b).input_sha256
    )
    reordered = (Ambiguity("z", "title", "unknown"), Ambiguity("a", "skills", "unknown"))
    assert (
        evaluate_feedback_eligibility(p, facts(), reordered, b).input_sha256
        == evaluate_feedback_eligibility(p, facts(), tuple(reversed(reordered)), b).input_sha256
    )
