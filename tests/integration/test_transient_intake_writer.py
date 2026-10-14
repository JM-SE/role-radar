"""Offline proof that description clarification precedes intake discard only."""

from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from role_radar.db.base import Base
from role_radar.db.models import Job, JobSearchRun, JobSourceReference, RunJob
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import SourceType
from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.transient_clarification import MAX_ATTEMPTS_PER_RUN
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.acquired_job_writer import AcquiredJobWriter


def _profile() -> dict[str, object]:
    return CandidateProfileV1.model_validate(
        {
            "title": None,
            "years_of_experience": None,
            "target_roles": ["frontend"],
            "target_titles": [],
            "core_skills": [],
            "secondary_skills": [],
            "regions": ["argentina"],
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
    ).model_dump(mode="json")


def test_writer_uses_bounded_clarification_and_persists_only_admitted_row(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'intake.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        profile = ProfileRepository(session).create_v1(name="test", profile_json=_profile())
        source = SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme"},
            enabled=True,
        )
        run = RunRepository(session).create_run("intake", profile_id=profile.id)
        session.commit()
        run_id, source_id = run.id, source.id

    jobs = (
        RawJob(
            source="greenhouse",
            external_id="eligible",
            title="Senior Frontend Engineer",
            company="Acme",
            location="Remote",
            source_url="https://boards.greenhouse.io/acme/jobs/eligible",
            application_url="https://boards.greenhouse.io/acme/jobs/eligible",
            description="Fully remote position. Work remotely from Argentina.",
            structured_data={"id": "eligible"},
            collected_at=datetime.now(UTC),
        ),
        RawJob(
            source="greenhouse",
            external_id="us-only",
            title="Senior Frontend Engineer",
            company="Acme",
            location="Remote - United States",
            source_url="https://boards.greenhouse.io/acme/jobs/us-only",
            application_url="https://boards.greenhouse.io/acme/jobs/us-only",
            description="Fully remote position. Work remotely from United States.",
            structured_data={"id": "us-only", "remote_policy": "remote"},
            collected_at=datetime.now(UTC),
        ),
    )
    with Session(engine) as session:
        result = AcquiredJobWriter(session).write(
            run_id=run_id,
            source_id=source_id,
            raw_jobs=jobs,
            max_clarification_attempts=1,
        )
        session.commit()
    assert result.clarification_attempts == 1
    assert result.accepted == 1
    assert result.profile_rejected == 1

    with Session(engine) as session:
        persisted = list(session.scalars(select(Job)).all())
        assert len(persisted) == 1
        reference = session.scalar(select(JobSourceReference))
        assert reference is not None
        assert reference.raw_payload["role_radar_intake_clarification"]["policy_version"] == (
            "description-clarification-v1"
        )
        assert "United States" not in str(reference.raw_payload)
        assert reference.raw_payload["role_radar_profile_intake"]["policy_version"] == (
            "profile-intake-v2"
        )
        assert reference.raw_payload["role_radar_profile_intake"]["intake_evidence"][
            "description_clarification"
        ] == reference.raw_payload["role_radar_intake_clarification"]
        assert list(session.scalars(select(RunJob)).all())


def test_writer_does_not_clarify_known_role_or_region_incompatibility(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'bounded-intake.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        profile = ProfileRepository(session).create_v1(name="test", profile_json=_profile())
        source = SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme"},
            enabled=True,
        )
        run = RunRepository(session).create_run("intake", profile_id=profile.id)
        session.commit()
        run_id, source_id = run.id, source.id
    job = RawJob(
        source="greenhouse",
        external_id="backend-us",
        title="Backend Engineer",
        company="Acme",
        location="Remote - United States",
        source_url="https://boards.greenhouse.io/acme/jobs/backend-us",
        application_url="https://boards.greenhouse.io/acme/jobs/backend-us",
        description="Fully remote position. Work remotely from Argentina.",
        structured_data={"id": "backend-us", "remote_policy": "remote"},
        collected_at=datetime.now(UTC),
    )
    with Session(engine) as session:
        result = AcquiredJobWriter(session).write(
            run_id=run_id,
            source_id=source_id,
            raw_jobs=(job,),
            max_clarification_attempts=MAX_ATTEMPTS_PER_RUN,
        )
        session.commit()
    assert result.clarification_attempts == 0
    assert result.profile_rejected == 1
    with Session(engine) as session:
        assert session.scalar(select(Job.id)) is None
        assert session.scalar(select(JobSourceReference.id)) is None
        assert session.scalar(select(RunJob.id)) is None
        run = session.get(JobSearchRun, run_id)
        assert run is not None
