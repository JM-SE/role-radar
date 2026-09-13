"""Append-only feedback revisions with idempotent replay and conflicts."""

from __future__ import annotations

import pytest

from role_radar.repositories.feedback import FeedbackConflictError, FeedbackRepository
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository


def seed_run_and_job(db_session) -> tuple[str, str]:
    run = RunRepository(db_session).create_run("test", profile_id=None)
    job = JobRepository(db_session).create(
        title="Backend Engineer",
        company="Acme",
        description="Python role",
        description_hash="0" * 64,
    )
    db_session.flush()
    return run.id, job.id


def test_submit_replay_and_revision_chain(db_session) -> None:
    run_id, job_id = seed_run_and_job(db_session)
    repo = FeedbackRepository(db_session)
    first, created = repo.submit(
        run_id=run_id, job_id=job_id, label="apply", primary_reason="skills_match"
    )
    assert created is True
    assert first.revision == 1
    same, replayed = repo.submit(
        run_id=run_id, job_id=job_id, label="apply", primary_reason="skills_match"
    )
    assert replayed is False
    assert same.id == first.id
    assert same.revision == 1
    changed, created_change = repo.submit(
        run_id=run_id,
        job_id=job_id,
        label="reject",
        primary_reason="role_mismatch",
        expected_revision=1,
    )
    assert created_change is True
    assert changed.revision == 2
    assert [row.revision for row in repo.history(run_id, job_id)] == [1, 2]


def test_expected_revision_conflict(db_session) -> None:
    run_id, job_id = seed_run_and_job(db_session)
    repo = FeedbackRepository(db_session)
    repo.submit(run_id=run_id, job_id=job_id, label="apply", primary_reason="skills_match")
    with pytest.raises(FeedbackConflictError):
        repo.submit(
            run_id=run_id,
            job_id=job_id,
            label="maybe",
            primary_reason="role_scope_unclear",
            expected_revision=7,
        )


def test_summary_counts_latest_labels_only(db_session) -> None:
    run_id, job_id = seed_run_and_job(db_session)
    other = JobRepository(db_session).create(
        title="Java Developer",
        company="Acme",
        description="Spring role",
        description_hash="1" * 64,
    )
    db_session.flush()
    repo = FeedbackRepository(db_session)
    repo.submit(run_id=run_id, job_id=job_id, label="apply", primary_reason="skills_match")
    repo.submit(run_id=run_id, job_id=job_id, label="reject", primary_reason="role_mismatch")
    repo.submit(run_id=run_id, job_id=other.id, label="maybe", primary_reason="role_scope_unclear")
    assert repo.summary(run_id) == {
        "run_id": run_id,
        "decided_jobs": 2,
        "labels": {"apply": 0, "maybe": 1, "reject": 1},
    }
