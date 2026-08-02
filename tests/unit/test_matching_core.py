"""Golden and metamorphic checks for the ORM-free matching core."""

from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import JobFacts
from role_radar.matching.engine import score_job
from role_radar.matching.profile_adapter import adapt_legacy_profile


def profile(**changes: object) -> CandidateProfileV1:
    payload: dict[str, object] = {
        "title": "senior backend engineer",
        "years_of_experience": 8,
        "target_roles": ["backend"],
        "target_titles": ["backend engineer"],
        "core_skills": ["python", "sql"],
        "secondary_skills": ["docker"],
        "regions": ["spain"],
        "remote_only": True,
        "employment_preferences": ["full_time"],
        "languages": {"english": "professional"},
        "excluded_roles": [],
        "excluded_technologies": [],
        "hard_constraints": {},
        "soft_preferences": {},
    }
    payload.update(changes)
    return CandidateProfileV1.model_validate(payload)


def facts(**changes: object) -> JobFacts:
    value = JobFacts(
        job_id="job-1",
        title="Backend Engineer",
        regions=("spain",),
        remote_policy="remote",
        required_skills=("python",),
        preferred_skills=("docker",),
        years_experience=5,
        employment_type="full_time",
        languages=(("english", "professional"),),
        title_provenance="ats",
        regions_provenance="ats",
        remote_provenance="ats",
        required_skills_provenance="extraction",
        preferred_skills_provenance="extraction",
        years_provenance="extraction",
        employment_provenance="ats",
        languages_provenance="extraction",
    )
    if "core_skills" in changes:
        value = replace(value, core_skills=tuple(changes["core_skills"]))  # type: ignore[arg-type,call-arg]
    if "regions" in changes:
        value = replace(value, regions=tuple(changes["regions"]))  # type: ignore[arg-type]
    if "required_skills" in changes:
        value = replace(value, required_skills=tuple(changes["required_skills"]))  # type: ignore[arg-type]
    return value


def test_golden_score_is_explainable_and_bounded() -> None:
    result = score_job(profile(), facts(), job_id="job-1", profile_id="profile-1")
    assert result.preliminary_score == sum(signal.points for signal in result.signals)
    assert 0 <= result.preliminary_score <= 100
    assert result.eligible is True
    assert [signal.name for signal in result.signals] == [
        "role_match",
        "location_match",
        "core_skill_match",
        "secondary_skill_match",
        "seniority_match",
        "employment_match",
        "language_match",
    ]


def test_explicit_blocker_does_not_skip_signals() -> None:
    result = score_job(
        profile(excluded_technologies=["python"]), facts(), job_id="job-1", profile_id="profile-1"
    )
    assert result.eligible is False
    assert [blocker.code for blocker in result.blockers] == ["excluded_required_technology"]
    assert len(result.signals) == 7


def test_permutations_and_duplicates_have_same_hash() -> None:
    first = score_job(profile(), facts(), job_id="job-1", profile_id="profile-1")
    second = score_job(
        profile(core_skills=["SQL", "python", "python"], regions=["SPAIN", "spain"]),
        facts(required_skills=("PYTHON", "python")),
        job_id="job-1",
        profile_id="profile-1",
    )
    assert first.input_hash == second.input_hash
    assert first.operation_key == second.operation_key


def test_legacy_adapter_never_enables_remote_only() -> None:
    adapted = adapt_legacy_profile(
        {
            "roles_target": ["Backend Engineer"],
            "skills": ["Python"],
            "regions": ["Spain"],
            "remote_ok": True,
            "exclusions": ["night shift"],
            "experience_years": 8,
            "languages": ["en"],
        }
    )
    assert adapted.profile.remote_only is False
    assert adapted.profile.target_titles == ("backend engineer",)
    assert adapted.profile.languages["english"] == "unknown"
    assert {item.code for item in adapted.ambiguities} == {
        "legacy_remote_preference",
        "legacy_exclusions_unclassified",
    }


@given(st.lists(st.sampled_from(["python", "sql", "docker"]), max_size=6))
def test_score_bounds_hold_for_duplicate_skill_inputs(skills: list[str]) -> None:
    result = score_job(
        profile(core_skills=skills), facts(required_skills=tuple(skills)),
        job_id="job-1", profile_id="profile-1",
    )
    assert 0 <= result.preliminary_score <= 100
    assert sum(signal.points for signal in result.signals) == result.preliminary_score
