from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import JobFacts, ProfileBinding
from role_radar.matching.facts import JobSnapshot, SourceReferenceSnapshot, build_job_facts
from role_radar.matching.product_eligibility import (
    POLICY_VERSION,
    evaluate_product_eligibility,
    validate_product_eligibility,
)


def profile() -> CandidateProfileV1:
    return CandidateProfileV1.model_validate(
        {
            "title": None,
            "years_of_experience": None,
            "target_roles": ["frontend", "full_stack"],
            "target_titles": ["senior software engineer"],
            "core_skills": [],
            "secondary_skills": [],
            "regions": ["argentina", "worldwide"],
            "remote_only": True,
            "employment_preferences": [],
            "languages": {},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {
                "available_work_authorizations": ["argentina"],
                "unavailable_work_authorizations": [],
                "allowed_employment_types": [],
                "allowed_remote_policies": [],
            },
            "soft_preferences": {},
        }
    )


def binding() -> ProfileBinding:
    return ProfileBinding("profile", 1, 1, "a" * 64)


def facts(**overrides: object) -> JobFacts:
    values: dict[str, object] = {
        "title": "senior frontend engineer",
        "regions": ("latam",),
        "remote_policy": "remote",
        "extraction_id": "extraction",
        "regions_provenance": "transient",
        "remote_provenance": "transient",
    }
    values.update(overrides)
    return JobFacts(**values)  # type: ignore[arg-type]


def test_latam_is_eligible_unless_argentina_is_explicitly_excluded() -> None:
    eligible = evaluate_product_eligibility(profile(), facts(), (), binding())
    assert eligible.eligible
    assert eligible.policy_version == POLICY_VERSION

    excluded = evaluate_product_eligibility(
        profile(), facts(excluded_regions=("argentina",)), (), binding()
    )
    assert not excluded.eligible
    assert "region_incompatible" in excluded.reason_codes


def test_unknown_geography_and_declared_unknown_authorization_fail_closed() -> None:
    unknown_region = evaluate_product_eligibility(
        profile(), facts(regions=()), (), binding()
    )
    assert not unknown_region.eligible
    assert "region_unknown" in unknown_region.reason_codes

    us_only = evaluate_product_eligibility(
        profile(), facts(regions=("united states",)), (), binding()
    )
    assert not us_only.eligible
    assert "region_incompatible" in us_only.reason_codes

    unknown_authorization = evaluate_product_eligibility(
        profile(), facts(authorization_required=True), (), binding()
    )
    assert not unknown_authorization.eligible
    assert "authorization_unknown" in unknown_authorization.reason_codes

    incompatible_authorization = evaluate_product_eligibility(
        profile(), facts(work_authorizations=("united states",)), (), binding()
    )
    assert not incompatible_authorization.eligible
    assert "work_authorization_unavailable" in incompatible_authorization.reason_codes


def test_no_declared_authorization_requirement_is_not_a_blocker() -> None:
    decision = evaluate_product_eligibility(profile(), facts(), (), binding())
    assert decision.eligible
    assert "authorization_unknown" not in decision.reason_codes


def test_legacy_product_eligibility_evidence_remains_readable() -> None:
    legacy = {
        "policy_version": "product-eligibility-v1",
        "profile_binding": binding().canonical_dict(),
        "input_sha256": "b" * 64,
        "eligible": True,
        "reason_codes": ["exact_region_match"],
        "extraction_id": "old-extraction",
    }
    assert validate_product_eligibility(legacy)


def test_transient_evidence_is_distinct_from_ats_and_compatible_latam_is_not_conflict() -> None:
    payload = {
        "role_radar_intake_clarification": {
            "policy_version": "description-clarification-v1",
            "remote_policy": "remote",
            "regions": ["argentina"],
            "excluded_regions": [],
            "conflict": False,
        },
        "regions": ["latam"],
        "remote_policy": "remote",
    }
    result = build_job_facts(
        JobSnapshot(
            id="job",
            title="Senior Frontend Engineer",
            source_references=(SourceReferenceSnapshot(id="ref", raw_payload=payload),),
        )
    )
    assert result.facts.regions == ("latam",)
    assert result.facts.regions_provenance == "ats"
    assert result.facts.remote_provenance == "ats"
    assert not result.ambiguities

    transient = build_job_facts(
        JobSnapshot(
            id="job",
            title="Senior Frontend Engineer",
            source_references=(
                SourceReferenceSnapshot(
                    id="ref",
                    raw_payload={
                        "role_radar_intake_clarification": {
                            **payload["role_radar_intake_clarification"],
                            "regions": ["latam"],
                        }
                    },
                ),
            ),
        )
    )
    assert transient.facts.regions == ("latam",)
    assert transient.facts.regions_provenance == "transient"
