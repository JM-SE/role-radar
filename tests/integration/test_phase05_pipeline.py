"""Offline F5 pipeline and lease tests using independent file-backed engines."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.db.base import Base
from role_radar.db.models import JobSearchRun
from role_radar.db.session import get_session_factory
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobSearchRunStatus, SourceType
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.run_service import RunService
from role_radar.worker.pipeline import Pipeline


def test_file_backed_claim_has_one_winner(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'claim.db'}"
    first_engine = create_engine(url)
    Base.metadata.create_all(first_engine)
    with Session(first_engine) as session:
        run = RunRepository(session).create_run("race")
        session.commit()
        run_id = run.id
    second_engine = create_engine(url)
    with Session(first_engine) as one, Session(second_engine) as two:
        assert RunRepository(one).claim_next(worker_id="one") is not None
        one.commit()
        assert RunRepository(two).claim_next(worker_id="two") is None
        two.commit()
    with Session(second_engine) as session:
        claimed = session.get(JobSearchRun, run_id)
        assert claimed is not None
        assert claimed.claimed_by == "one"


def test_pipeline_fake_completes_and_replay_is_effectively_once(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'pipeline.db'}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)
    fixtures = Path(__file__).parents[2] / "fixtures"
    with Session(engine) as session:
        profile_data = json.loads((fixtures / "profile_seed.json").read_text())
        profile = ProfileRepository(session).create_v1(
            name=profile_data["name"], profile_json=profile_data["profile_json"]
        )
        SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme", "company": "Acme"},
        )
        run = RunService(session).create(reason="offline", profile_id=profile.id)
        session.commit()
        run_id = run.id

    class FakeCollector:
        async def collect(self, _snapshot: object) -> list[RawJob]:
            return [
                RawJob(
                    source="greenhouse",
                    external_id="123",
                    source_url="https://boards.greenhouse.io/acme/jobs/123",
                    application_url="https://boards.greenhouse.io/acme/jobs/123",
                    title="Backend Engineer",
                    company="Acme",
                    description="Build and operate the core API platform at Acme.",
                    collected_at=datetime.now(UTC),
                )
            ]

    provider = FakeLLMProvider(fixture=fixtures / "extraction_valid.json")
    pipeline = Pipeline(
        factory,
        provider=provider,
        collector_factory=lambda _snapshot: FakeCollector(),
    )
    asyncio.run(pipeline.run(run_id))
    asyncio.run(pipeline.run(run_id))
    with Session(engine) as session:
        completed = session.get(JobSearchRun, run_id)
        assert completed is not None
        assert completed.status is JobSearchRunStatus.COMPLETED
        assert completed.stats_json is not None
        assert completed.stats_json["new_jobs"] == 1
        assert completed.stats_json["scored"] == 1
        assert len(completed.run_jobs) == 5
