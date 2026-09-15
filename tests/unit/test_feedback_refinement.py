"""Group-attributed refinement proposals and validated successor policies."""

from __future__ import annotations

import tomllib
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from role_radar.db.models import CandidateProfile, JobSearchRun
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.domain.enums import DiscoveryMode, RunJobStage, RunJobStatus
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.run_jobs import RunJobRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.feedback_refinement import (
    apply_refinement,
    emit_policy_toml,
    policy_payload,
    propose_refinement,
)
from role_radar.services.feedback_service import submit_feedback

PROFILE_PAYLOAD = {
    "title": "backend engineer",
    "years_of_experience": 8,
    "target_roles": ["backend"],
    "target_titles": ["backend engineer"],
    "core_skills": ["python"],
    "secondary_skills": [],
    "regions": ["europe"],
    "remote_only": True,
    "employment_preferences": ["full_time"],
    "languages": {"english": "professional"},
    "excluded_roles": [],
    "excluded_technologies": [],
    "hard_constraints": {
        "available_work_authorizations": [],
        "unavailable_work_authorizations": [],
        "allowed_employment_types": [],
        "allowed_remote_policies": [],
    },
    "soft_preferences": {"preferred_industries": []},
}


def make_policy(profile_id: str, payload: dict[str, Any], version: str) -> DiscoveryPolicyV1:
    return DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": version,
            "profile_binding": {
                "profile_id": profile_id,
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": canonical_profile_sha256(payload),
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {
                "backend": ("Backend Engineer",),
                "legacy": ("COBOL",),
            },
            "target_roles": {"backend": {"primary_groups": ["backend"]}},
            "target_titles": {
                "backend engineer": {
                    "primary_groups": ["backend"],
                    "coverage_groups": ["legacy"],
                }
            },
        }
    )


def seed_run(db_session: Session) -> tuple[str, str]:
    profile_id = str(uuid4())
    db_session.add(
        CandidateProfile(
            id=profile_id,
            name=f"qa-{profile_id[:8]}",
            version=1,
            schema_version=1,
            profile_json={},
            is_active=True,
        )
    )
    run = RunRepository(db_session).create_run(
        "test", profile_id=profile_id, discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    DiscoveryRepository(db_session).create_cycle(
        run_id=run.id,
        profile_snapshot={"profile_binding": {
            "profile_id": profile_id, "row_version": 1, "schema_version": 1,
            "canonical_profile_sha256": "0" * 64,
        }},
        planner_version="discovery-planner-v2", planner_hash="0" * 64,
        policy_version="gate-a-v1",
    )
    db_session.flush()
    return run.id, profile_id


def seed_job(db_session: Session, run_id: str, title: str, description: str) -> str:
    job = JobRepository(db_session).create(
        title=title,
        company="Acme",
        description=description,
        description_hash=str(uuid4()).replace("-", ""),
    )
    row = RunJobRepository(db_session).claim_attempt(
        run_id=run_id,
        job_id=job.id,
        stage=RunJobStage.DEDUPLICATED,
        max_attempts=3,
        now=datetime.now(UTC),
    )
    assert row is not None
    RunJobRepository(db_session).finish(
        row, status=RunJobStatus.SUCCEEDED, outcome={"acquisition": "discovery"}
    )
    db_session.flush()
    run = db_session.get(JobSearchRun, run_id)
    assert run is not None
    scored = RunJobRepository(db_session).claim_attempt(
        run_id=run_id, job_id=job.id, stage=RunJobStage.SCORED,
        max_attempts=3, now=datetime.now(UTC)
    )
    assert scored is not None
    RunJobRepository(db_session).finish(
        scored, status=RunJobStatus.SUCCEEDED,
        outcome={"feedback_eligibility": {
            "policy_version": "feedback-remote-eligibility-v1",
            "profile_binding": {
                "profile_id": run.profile_id, "row_version": 1,
                "schema_version": 1, "canonical_profile_sha256": "0" * 64,
            },
            "input_sha256": "1" * 64, "eligible": True,
            "reason_codes": ["exact_region_match"], "extraction_id": "fixture-extraction",
        }},
    )
    db_session.flush()
    return job.id


def seed_decisions(db_session: Session, run_id: str) -> None:
    for index in range(3):
        job_id = seed_job(db_session, run_id, "Java Developer", f"COBOL maintenance role {index}")
        submit_feedback(
            db_session,
            run_id=run_id,
            job_id=job_id,
            label="reject",
            primary_reason="skills_mismatch",
        )
    keeper = seed_job(db_session, run_id, "Backend Engineer", "Backend Engineer with Python")
    submit_feedback(
        db_session,
        run_id=run_id,
        job_id=keeper,
        label="apply",
        primary_reason="skills_match",
    )
    db_session.commit()


def test_propose_flags_zero_precision_coverage(db_session: Session) -> None:
    run_id, profile_id = seed_run(db_session)
    seed_decisions(db_session, run_id)
    proposal = propose_refinement(
        db_session, run_id, make_policy(profile_id, PROFILE_PAYLOAD, "gate-a-v1")
    )
    assert proposal["removals"] == ["legacy"]
    by_group = {entry["group_id"]: entry for entry in proposal["groups"]}
    assert by_group["legacy"]["action"] == "remove"
    assert by_group["legacy"]["decisions"] == 3
    assert by_group["legacy"]["precision"] == 0
    assert by_group["backend"]["action"] == "keep"
    assert by_group["backend"]["primary"] is True
    assert by_group["legacy"]["primary"] is False


def test_propose_respects_decision_threshold(db_session: Session) -> None:
    run_id, profile_id = seed_run(db_session)
    job_id = seed_job(db_session, run_id, "Java Developer", "COBOL maintenance role")
    submit_feedback(
        db_session,
        run_id=run_id,
        job_id=job_id,
        label="reject",
        primary_reason="skills_mismatch",
    )
    db_session.commit()
    proposal = propose_refinement(
        db_session,
        run_id,
        make_policy(profile_id, PROFILE_PAYLOAD, "gate-a-v1"),
        min_decisions=3,
    )
    assert proposal["removals"] == []


def test_apply_emits_validated_successor(db_session: Session) -> None:
    run_id, profile_id = seed_run(db_session)
    seed_decisions(db_session, run_id)
    policy = make_policy(profile_id, PROFILE_PAYLOAD, "gate-a-v1")
    proposal = propose_refinement(db_session, run_id, policy)
    text = apply_refinement(policy, proposal["removals"], new_policy_version="gate-a-v2")
    reparsed = DiscoveryPolicyV1.model_validate(tomllib.loads(text))
    assert reparsed.policy_version == "gate-a-v2"
    assert set(reparsed.groups) == {"backend"}
    assert reparsed.profile_binding == policy.profile_binding
    assert "legacy" not in text


def test_apply_rejects_empty_unknown_and_primary() -> None:
    policy = make_policy(str(uuid4()), PROFILE_PAYLOAD, "gate-a-v1")
    with pytest.raises(ValueError):
        apply_refinement(policy, [], new_policy_version="gate-a-v2")
    with pytest.raises(ValueError):
        apply_refinement(policy, ["missing"], new_policy_version="gate-a-v2")
    with pytest.raises(ValueError):
        apply_refinement(policy, ["backend"], new_policy_version="gate-a-v2")


def test_emit_policy_toml_round_trips() -> None:
    policy = make_policy(str(uuid4()), PROFILE_PAYLOAD, "gate-a-v1")
    text = emit_policy_toml(policy_payload(policy))
    assert DiscoveryPolicyV1.model_validate(tomllib.loads(text)) == policy
