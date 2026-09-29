"""Jobicy due collection persists profile-compatible remote LATAM jobs."""

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.db.models import JobSourceReference, SourcePollState
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import DiscoveryMode, SourceType
from role_radar.free_sources.terms import (
    JOBICY_TERMS_POLICY_VERSION,
    JobicyTermsAcceptance,
)
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.pipeline_free_sources import PipelineFreeSourcesService
from role_radar.services.source_service import SourceService


class FakeJobicyCollector:
    async def collect(self, _snapshot: object, _runtime: object) -> CollectionSuccess:
        job = RawJob(
            source="jobicy",
            external_id="job-1",
            source_url="https://jobicy.com/jobs/job-1",
            application_url="https://jobicy.com/jobs/job-1",
            title="Backend Engineer",
            company="Acme",
            location="LATAM",
            description="Build APIs",
            published_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
            collected_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
        )
        return CollectionSuccess(
            status="ok",
            jobs=(job,),
            metrics=CollectionMetrics(provider_items=1, accepted_items=1),
        )


async def test_jobicy_reservation_writer_and_second_due_run(
    db_engine: Engine, db_session: Session
) -> None:
    profile_data = json.loads(
        (Path(__file__).parents[2] / "fixtures" / "profile_seed.json").read_text()
    )
    profile_data["profile_json"]["regions"] = ["latam", "spain", "europe"]
    profile = ProfileRepository(db_session).create_v1(
        name=profile_data["name"], profile_json=profile_data["profile_json"]
    )
    source = SourceService(db_session).create(
        source_type=SourceType.JOBICY,
        name="Jobicy LATAM",
        configuration={"region": "latam", "remote_only": True},
    )
    source.enabled = True
    run = RunRepository(db_session).create_run(
        "scheduled",
        profile_id=profile.id,
        discovery_mode=DiscoveryMode.SCHEDULED_DUE,
        schedule_slot="2026-08-09T12:00:00Z",
    )
    db_session.commit()
    acceptance = JobicyTermsAcceptance(
        terms_url="https://jobicy.com/terms-and-conditions",
        reviewed_at=datetime(2026, 8, 9, 12, tzinfo=UTC),
        policy_version=JOBICY_TERMS_POLICY_VERSION,
        fair_use_ack=True,
        preserve_destination_ack=True,
        no_redistribution_ack=True,
    )
    service = PipelineFreeSourcesService(
        lambda: Session(db_engine),
        terms=acceptance,
        collector_factory=lambda _snapshot: FakeJobicyCollector(),
        clock=lambda: datetime(2026, 8, 9, 12, tzinfo=UTC),
    )

    plan = service.prepare(run.id)
    assert plan.counters.due == 1
    assert len(plan.reserved_tasks) == 1
    replay = service.prepare(run.id)
    assert replay.reserved_tasks[0].operation_id == plan.reserved_tasks[0].operation_id
    execution = await service.execute(replay.tasks[0])
    service.finalize(run.id, execution)

    with Session(db_engine) as check:
        state = check.scalar(select(SourcePollState).where(SourcePollState.source_id == source.id))
        assert state is not None
        assert state.last_request_at is not None
        assert state.last_success_at is not None
        assert (
            check.scalar(
                select(JobSourceReference).where(JobSourceReference.source_id == source.id)
            )
            is not None
        )

    second = service.prepare(run.id)
    assert second.counters.due == 0
    assert second.tasks == ()
