"""Offline Job + extraction + profile integration for F4."""

from sqlalchemy.orm import Session

from role_radar.domain.enums import ExtractionStatus
from role_radar.repositories.extractions import ExtractionRepository
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.profiles import ProfileRepository
from role_radar.services.matching_service import MatchingService


def test_matching_persists_and_replays_same_operation(db_session: Session) -> None:
    profile = ProfileRepository(db_session).create_v1(
        name="F4",
        profile_json={
            "title": "backend engineer",
            "years_of_experience": 8,
            "target_roles": ["backend"],
            "target_titles": ["backend engineer"],
            "core_skills": ["python"],
            "secondary_skills": [],
            "regions": ["spain"],
            "remote_only": True,
            "employment_preferences": ["full_time"],
            "languages": {},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {},
            "soft_preferences": {},
        },
    )
    job = JobRepository(db_session).create(
        title="Backend Engineer", company="Acme", location="Spain", description_hash="a" * 64
    )
    db_session.commit()
    extraction = ExtractionRepository(db_session).add(
        job_id=job.id,
        schema_version="job-extraction-1",
        prompt_version="prompt-1",
        model_capability="structured-extraction",
        input_hash="a" * 64,
        status=ExtractionStatus.VALID,
    )
    ExtractionRepository(db_session).update_result(
        extraction.id,
        payload={"required_skills": [{"value": "python", "evidence": "Python"}]},
    )
    db_session.commit()

    first, decision = MatchingService(db_session).score_job_with_eligibility(
        job_id=job.id, profile_id=profile.id
    )
    assert decision.extraction_id is None
    assert "remote_policy_unknown" in decision.reason_codes
    assert decision.profile_binding.profile_id == profile.id
    assert decision.input_sha256
    db_session.commit()
    second = MatchingService(db_session).score_job(job_id=job.id, profile_id=profile.id)
    assert first.id == second.id
    assert first.extraction_id == extraction.id
    assert first.input_hash == second.input_hash
