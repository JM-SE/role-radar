"""Current product feedback surface, rendering, decisions and summary."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from role_radar.db.models import CandidateProfile
from role_radar.domain.enums import DiscoveryMode, RunJobStage, RunJobStatus
from role_radar.evaluation.blind_labeling.validation import ValidationError
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.run_jobs import RunJobRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.feedback_service import (
    build_surface,
    collect_candidates,
    render_candidate,
    submit_feedback,
    summarize,
)

PHRASES = ["Backend Engineer"]


def seed_run(db_session, approved=PHRASES) -> str:
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
        profile_snapshot={"approved_phrases": list(approved)},
        planner_version="discovery-planner-v2",
        planner_hash="0" * 64,
        policy_version="gate-a-v1",
    )
    db_session.flush()
    return run.id


def seed_job(db_session, run_id: str, title: str, description: str) -> str:
    job = JobRepository(db_session).create(
        title=title,
        company="Acme",
        location="Remote",
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
    return job.id


def seed_surface(db_session) -> tuple[str, str, str, str, str]:
    run_id = seed_run(db_session)
    relevant = seed_job(
        db_session, run_id, "Backend Engineer", "Backend Engineer with Python daily"
    )
    near = seed_job(db_session, run_id, "Java Developer", "Backend Engineer background is a plus")
    unrelated = seed_job(db_session, run_id, "Java Developer", "Spring shop role")
    excluded = seed_job(db_session, run_id, "Backend Engineer", "   ")
    return run_id, relevant, near, unrelated, excluded


def test_surface_orders_bands_and_counts(db_session) -> None:
    run_id, relevant, near, unrelated, _excluded = seed_surface(db_session)
    surface = build_surface(db_session, run_id)
    assert [item.job_id for item in surface.items] == [relevant, near, unrelated]
    assert [item.band for item in surface.items] == ["relevant", "near_miss", "unrelated"]
    assert surface.items[0].matched_phrases == ("Backend Engineer",)
    assert surface.excluded_count == 1
    assert surface.approved_phrases == tuple(PHRASES)
    assert {item.job_id for item in collect_candidates(db_session, run_id)} == {
        relevant,
        near,
        unrelated,
        _excluded,
    }


def test_render_uses_display_v2(db_session) -> None:
    run_id, relevant, *_ = seed_surface(db_session)
    candidate = next(
        item for item in collect_candidates(db_session, run_id) if item.job_id == relevant
    )
    rendered = render_candidate(candidate, index=1, total=4)
    assert "Backend Engineer" in rendered
    assert "Acme" in rendered


def test_submit_decide_and_resume(db_session) -> None:
    run_id, relevant, near, *_ = seed_surface(db_session)
    row, created = submit_feedback(
        db_session,
        run_id=run_id,
        job_id=relevant,
        label="apply",
        primary_reason="skills_match",
    )
    assert created is True
    assert row.revision == 1
    db_session.commit()
    surface = build_surface(db_session, run_id)
    decided = next(item for item in surface.items if item.job_id == relevant)
    assert decided.revision == 1
    assert decided.decision is not None and decided.decision["label"] == "apply"
    pending = [item.job_id for item in surface.items if item.decision is None]
    assert pending == [near, surface.items[2].job_id]


def test_submit_rejects_unknown_job(db_session) -> None:
    run_id, *_ = seed_surface(db_session)
    with pytest.raises(LookupError):
        submit_feedback(
            db_session,
            run_id=run_id,
            job_id="missing",
            label="apply",
            primary_reason="skills_match",
        )


def test_submit_enforces_note_rules(db_session) -> None:
    run_id, relevant, *_ = seed_surface(db_session)
    with pytest.raises(ValidationError):
        submit_feedback(
            db_session,
            run_id=run_id,
            job_id=relevant,
            label="reject",
            primary_reason="other_negative",
        )
    with pytest.raises(ValidationError):
        submit_feedback(
            db_session,
            run_id=run_id,
            job_id=relevant,
            label="apply",
            primary_reason="skills_match",
            note="stray note",
        )
    row, created = submit_feedback(
        db_session,
        run_id=run_id,
        job_id=relevant,
        label="reject",
        primary_reason="other_negative",
        note="night shifts only",
    )
    assert created is True
    assert row.note == "night shifts only"


def test_summary_reports_bands(db_session) -> None:
    run_id, relevant, near, *_ = seed_surface(db_session)
    submit_feedback(
        db_session, run_id=run_id, job_id=relevant, label="apply", primary_reason="skills_match"
    )
    submit_feedback(
        db_session, run_id=run_id, job_id=near, label="maybe", primary_reason="role_scope_unclear"
    )
    db_session.commit()
    report = summarize(db_session, run_id)
    assert report["decided_jobs"] == 2
    assert report["labels"] == {"apply": 1, "maybe": 1, "reject": 0}
    assert report["decided_bands"] == {"relevant": 1, "near_miss": 1}
    assert report["candidates"] == 3
