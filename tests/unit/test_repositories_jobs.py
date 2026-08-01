"""Tests unitarios de JobRepository, SourceRepository y RunRepository."""

from sqlalchemy.orm import Session

from role_radar.domain.enums import (
    JobSearchRunStatus,
    JobStatus,
    RunJobStage,
    RunJobStatus,
    SourceType,
)
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository


def test_job_create_and_get(db_session: Session) -> None:
    repo = JobRepository(db_session)
    job = repo.create(title="Backend Engineer", company="Acme")
    db_session.commit()

    assert job.id
    assert job.status == JobStatus.NEW
    fetched = repo.get(job.id)
    assert fetched is not None
    assert fetched.title == "Backend Engineer"
    assert fetched.company == "Acme"


def test_job_get_unknown_returns_none(db_session: Session) -> None:
    repo = JobRepository(db_session)
    assert repo.get("no-existe") is None


def test_job_list_filters(db_session: Session) -> None:
    repo = JobRepository(db_session)
    repo.create(title="Job 1", company="Acme", status=JobStatus.NEW)
    repo.create(title="Job 2", company="Beta", status=JobStatus.ACTIVE)
    db_session.commit()

    assert len(repo.list()) == 2
    assert len(repo.list(status=JobStatus.ACTIVE)) == 1
    assert len(repo.list(company="Acme")) == 1
    assert len(repo.list(limit=1)) == 1
    assert len(repo.list(offset=1)) == 1


def test_add_source_reference(db_session: Session) -> None:
    source = SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE, name="Acme Greenhouse"
    )
    job = JobRepository(db_session).create(title="Backend Engineer", company="Acme")
    db_session.commit()

    ref = JobRepository(db_session).add_source_reference(
        job_id=job.id,
        source_id=source.id,
        external_id="ext-123",
        source_url="https://boards.greenhouse.io/acme/jobs/ext-123",
        raw_payload={"location": "Remote"},
    )
    db_session.commit()

    assert ref.id
    fetched = JobRepository(db_session).get(job.id)
    assert fetched is not None
    assert len(fetched.source_references) == 1
    assert fetched.source_references[0].external_id == "ext-123"
    assert fetched.source_references[0].raw_payload == {"location": "Remote"}


def test_source_repository(db_session: Session) -> None:
    repo = SourceRepository(db_session)
    source = repo.create(
        type=SourceType.MANUAL,
        name="Manual",
        configuration={"note": "seed"},
        enabled=False,
    )
    db_session.commit()

    assert repo.get(source.id) is not None
    assert repo.get_by_name("Manual") is not None
    assert repo.get_by_name("Inexistente") is None


def test_run_repository(db_session: Session) -> None:
    job = JobRepository(db_session).create(title="Job", company="Acme")
    db_session.commit()

    repo = RunRepository(db_session)
    run = repo.create_run(reason="test run")
    db_session.commit()
    assert run.status == JobSearchRunStatus.PENDING

    run_job = repo.add_run_job(
        run_id=run.id,
        job_id=job.id,
        stage=RunJobStage.COLLECTED,
        status=RunJobStatus.SUCCEEDED,
    )
    db_session.commit()

    assert repo.get_run(run.id) is not None
    assert repo.get_run("no-existe") is None
    assert run_job.run_id == run.id
    assert run_job.stage == RunJobStage.COLLECTED
