"""Regression cases for public ATS titles against a minimal real-profile projection.

The projection contains only fields relevant to role/location admission. Other
profile fields are neutral test values; the complete profile is never persisted
in the test suite.
"""

from datetime import UTC, datetime
from hashlib import sha256

import pytest

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.domain.dto import NormalizedJob
from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import JobFacts, ProfileBinding, ProfileIntakeDecision
from role_radar.matching.policy import ScoringPolicyV1
from role_radar.matching.profile_intake import evaluate_profile_intake
from role_radar.matching.signals import role_match
from role_radar.matching.transient_clarification import clarify_description
from role_radar.normalization.jobs import normalize_raw_job

PROFILE_ID = "e4aec18c-90fa-4553-ae3e-9e4655223683"
PROFILE_VERSION = 2


def real_profile_projection() -> CandidateProfileV1:
    """Build a minimal fixture from the locally verified profile fields."""
    return CandidateProfileV1.model_validate(
        {
            "title": None,
            "years_of_experience": None,
            "target_roles": ["frontend", "frontend architect", "full_stack", "staff frontend"],
            "target_titles": [
                "frontend architect",
                "senior frontend developer",
                "senior frontend engineer",
                "senior full stack engineer",
                "senior software engineer",
                "staff frontend engineer",
            ],
            "core_skills": [],
            "secondary_skills": [],
            "regions": ["argentina", "worldwide"],
            "remote_only": True,
            "employment_preferences": ["full_time", "contractor"],
            "languages": {},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {
                "available_work_authorizations": ["argentina"],
                "unavailable_work_authorizations": [],
                "allowed_employment_types": ["contractor", "full_time"],
                "allowed_remote_policies": [],
            },
            "soft_preferences": {},
        }
    )


def profile_binding() -> ProfileBinding:
    # Stable fixture digest, not a digest or disclosure of the complete profile.
    return ProfileBinding(
        profile_id=PROFILE_ID,
        row_version=PROFILE_VERSION,
        schema_version=1,
        canonical_profile_sha256=sha256(b"minimal-role-intake-test-projection").hexdigest(),
    )


CASES = (
    pytest.param(
        "Senior Frontend Engineer, Ads Creative",
        "reddit",
        "8175520",
        20,
        True,
        id="reddit-senior-frontend-engineer-ads-creative",
    ),
    pytest.param(
        "Senior Software Engineer, Consumer Engineering",
        "reddit",
        "8187247",
        0,
        False,
        id="reddit-qualified-senior-software-engineer",
    ),
    pytest.param(
        "Senior Software Engineer, Frontend",
        "example",
        "frontend-qualified",
        15,
        True,
        id="qualified-software-engineer-frontend",
    ),
    pytest.param(
        "Senior Software Engineer, Full Stack",
        "example",
        "full-stack-qualified",
        15,
        True,
        id="qualified-software-engineer-full-stack",
    ),
    pytest.param(
        "Senior Software Engineer, Backend",
        "example",
        "backend-qualified",
        0,
        False,
        id="qualified-software-engineer-backend",
    ),
    pytest.param(
        "Senior Frontend Engineer - Backend",
        "example",
        "conflicting-frontend-backend",
        0,
        False,
        id="conflicting-role-qualifier-is-not-stripped",
    ),
    pytest.param(
        "Senior Frontend Engineer, Backend",
        "example",
        "comma-qualified-frontend-backend",
        0,
        False,
        id="conflicting-comma-qualified-role-is-not-stripped",
    ),
    pytest.param(
        "Senior Frontend Engineer, Backend | Remote",
        "example",
        "compound-comma-qualified-frontend-backend",
        0,
        False,
        id="compound-conflicting-role-qualifier-is-not-stripped",
    ),
    pytest.param(
        "Senior Frontend Engineer, Backend, Frontend",
        "example",
        "mixed-frontend-backend-qualifiers",
        0,
        False,
        id="mixed-target-and-contradictory-qualifiers-reject",
    ),
    pytest.param(
        "Frontend Business Lead",
        "okx",
        "7684591003",
        0,
        False,
        id="okx-frontend-business-lead",
    ),
    pytest.param(
        "Senior Software Engineer",
        "reddit",
        "8187247",
        15,
        True,
        id="control-exact-senior-software-engineer",
    ),
)


@pytest.mark.parametrize(
    ("title", "board", "job_id", "expected_role_points", "expected_eligible"), CASES
)
def test_real_profile_public_title_role_and_full_intake(
    title: str,
    board: str,
    job_id: str,
    expected_role_points: int,
    expected_eligible: bool,
) -> None:
    profile = real_profile_projection()
    binding = profile_binding()

    role, ambiguities = role_match(
        profile,
        JobFacts(title=title, title_provenance="ats"),
        ScoringPolicyV1().maxima["role_match"],
    )
    assert role.points == expected_role_points
    assert ("role_mismatch" in role.reason_codes) is (expected_role_points == 0)
    assert not ambiguities

    # These explicit facts isolate title behavior in full intake. They are
    # fixture inputs, not claims that the public listings supplied this metadata.
    normalized = NormalizedJob(
        source="greenhouse",
        external_id=job_id,
        source_url=f"https://job-boards.greenhouse.io/{board}/jobs/{job_id}",
        application_url=f"https://job-boards.greenhouse.io/{board}/jobs/{job_id}",
        title=title,
        company=board,
        location="Remote - Worldwide",
        description="Test fixture description.",
        structured_data={
            "remote_policy": "remote",
            "regions": ["worldwide"],
            "employment_type": "full_time",
        },
        collected_at=datetime(2026, 9, 25, tzinfo=UTC),
    )
    decision = evaluate_profile_intake(
        profile,
        normalized,
        source_type="greenhouse",
        source_configuration={"board_token": board},
        profile_binding=binding,
    )

    assert decision.eligible is expected_eligible
    if expected_eligible:
        assert decision.reason_codes == ("worldwide",)
        assert decision.application_url == normalized.application_url
    else:
        assert decision.reason_codes == ("role_mismatch",)
        assert decision.application_url is None


def greenhouse_intake_decision(
    location: str,
    *,
    structured_data: dict[str, object] | None = None,
    description: str = "Fixture description.",
) -> ProfileIntakeDecision:
    raw = GreenhouseCollector._raw_values(
        {
            "id": "region-regression",
            "title": "Senior Frontend Engineer",
            "location": {"name": location},
            "absolute_url": "https://job-boards.greenhouse.io/example/jobs/1",
            "content": description,
        },
        "example",
        "Example",
    )
    normalized = normalize_raw_job(raw)
    # Region/modality test metadata is passed explicitly like provider evidence;
    # it is not derived from a job description or a profile change.
    normalized.structured_data.update(structured_data or {})
    return evaluate_profile_intake(
        real_profile_projection(),
        normalized,
        source_type="greenhouse",
        source_configuration={},
        profile_binding=profile_binding(),
        clarification=clarify_description(description),
    )


def test_greenhouse_us_only_location_is_rejected_and_viable_regions_remain() -> None:
    us = greenhouse_intake_decision(
        "Remote - United States", structured_data={"remote_policy": "remote"}
    )
    assert not us.eligible
    assert us.reason_codes == ("region_incompatible",)
    assert us.intake_evidence is not None
    assert us.intake_evidence["regions"] == ["united states"]

    argentina = greenhouse_intake_decision(
        "Remote - Argentina", structured_data={"remote_policy": "remote"}
    )
    assert argentina.eligible
    assert argentina.reason_codes == ("exact_region_match",)

    worldwide = greenhouse_intake_decision(
        "Remote - Worldwide", structured_data={"remote_policy": "remote"}
    )
    assert worldwide.eligible
    assert worldwide.reason_codes == ("worldwide",)


def test_greenhouse_unknown_remote_policy_remains_a_separate_blocker() -> None:
    unknown = greenhouse_intake_decision("United States")
    assert not unknown.eligible
    assert unknown.reason_codes == ("remote_policy_unknown", "region_incompatible")


def test_region_unknown_is_never_labeled_exact_match() -> None:
    unknown = greenhouse_intake_decision(
        "Remote", structured_data={"remote_policy": "remote"}
    )
    assert not unknown.eligible
    assert "region_unknown" in unknown.reason_codes

    argentina_only_profile = real_profile_projection().model_copy(
        update={"regions": ("argentina",)}
    )
    no_region_job = NormalizedJob(
        source="greenhouse",
        external_id="missing-region",
        source_url="https://job-boards.greenhouse.io/example/jobs/missing-region",
        application_url="https://job-boards.greenhouse.io/example/jobs/missing-region",
        title="Senior Frontend Engineer",
        company="example",
        location="Remote",
        description="Fixture.",
        structured_data={"remote_policy": "remote"},
        collected_at=datetime(2026, 9, 25, tzinfo=UTC),
    )
    decision = evaluate_profile_intake(
        argentina_only_profile,
        no_region_job,
        source_type="greenhouse",
        source_configuration={},
        profile_binding=profile_binding(),
    )
    assert not decision.eligible
    assert "region_unknown" in decision.reason_codes

    empty_profile_regions = real_profile_projection().model_copy(update={"regions": ()})
    worldwide_job = NormalizedJob(
        source="greenhouse",
        external_id="worldwide-no-profile-region",
        source_url="https://job-boards.greenhouse.io/example/jobs/worldwide",
        application_url="https://job-boards.greenhouse.io/example/jobs/worldwide",
        title="Senior Frontend Engineer",
        company="example",
        location="Remote - Worldwide",
        description="Fixture.",
        structured_data={"remote_policy": "remote", "regions": ["worldwide"]},
        collected_at=datetime(2026, 9, 25, tzinfo=UTC),
    )
    no_profile_region = evaluate_profile_intake(
        empty_profile_regions,
        worldwide_job,
        source_type="greenhouse",
        source_configuration={},
        profile_binding=profile_binding(),
    )
    assert not no_profile_region.eligible
    assert "profile_region_unknown" in no_profile_region.reason_codes


def test_latam_scope_includes_argentina_unless_explicitly_excluded() -> None:
    latam = greenhouse_intake_decision(
        "Remote - Latin America",
        structured_data={"remote_policy": "remote", "regions": ["latam"]},
    )
    assert latam.eligible

    excluded = greenhouse_intake_decision(
        "Remote - Latin America, excluding Argentina",
        structured_data={
            "remote_policy": "remote",
            "regions": ["latam"],
            "excluded_regions": ["argentina"],
        },
    )
    assert not excluded.eligible
    assert "region_incompatible" in excluded.reason_codes


def test_description_conflicting_with_ats_region_is_rejected() -> None:
    decision = greenhouse_intake_decision(
        "Remote - United States",
        structured_data={"remote_policy": "remote"},
        description="Fully remote position. Work remotely from Argentina.",
    )
    assert not decision.eligible
    assert "region_conflict" in decision.reason_codes
