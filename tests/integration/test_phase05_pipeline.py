"""Offline F5 pipeline and lease tests using independent file-backed engines."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.db.base import Base
from role_radar.db.models import Job, JobSearchRun, JobSourceReference, RunJob
from role_radar.db.session import get_session_factory
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobSearchRunStatus, SourceType
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.pipeline_collection import PipelineCollectionService
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
        async def collect(
            self, _snapshot: SourceSnapshot, _runtime: CollectorRuntime
        ) -> list[RawJob]:
            return [
                RawJob(
                    source="greenhouse",
                    external_id="123",
                    source_url="https://boards.greenhouse.io/acme/jobs/123",
                    application_url="https://boards.greenhouse.io/acme/jobs/123",
                    title="Backend Engineer",
                    company="Acme",
                    location="Remote Spain",
                    description="Build and operate the core API platform at Acme.",
                    structured_data={"remote_policy": "remote", "regions": ["spain"]},
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
        stats = completed.stats_json
        assert stats is not None
        manifest = stats["product_eligibility_reprocessing"]
        assert manifest["complete"] is True
        assert manifest["pending"] == 0
        assert manifest["eligible"] + manifest["excluded"] == manifest["total"]
        assert stats["new_jobs"] == 1
        assert stats["scored"] == 1
        assert len(completed.run_jobs) == 5


def test_restrictive_profile_preserves_broad_acquisition_contract(tmp_path: Path) -> None:
    def run_collection(db_name: str, regions: list[str]) -> dict[str, Any]:
        engine = create_engine(f"sqlite:///{tmp_path / db_name}")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            data = json.loads(
                (Path(__file__).parents[2] / "fixtures" / "profile_seed.json").read_text()
            )
            data["profile_json"]["regions"] = regions
            profile = ProfileRepository(session).create_v1(
                name="test", profile_json=data["profile_json"]
            )
            source = SourceRepository(session).create(
                type=SourceType.GREENHOUSE,
                name="Acme",
                configuration={"board_token": "acme", "company": "Acme"},
            )
            run = RunService(session).create(reason="broad", profile_id=profile.id)
            session.commit()
            run_id, source_id = run.id, source.id

        calls: list[SourceSnapshot] = []

        class Collector:
            async def collect(
                self, snapshot: SourceSnapshot, _runtime: CollectorRuntime
            ) -> CollectionSuccess:
                calls.append(snapshot)
                return CollectionSuccess(
                    status="ok",
                    jobs=(
                        RawJob(
                            source="greenhouse",
                            external_id="same-job",
                            source_url="https://boards.greenhouse.io/acme/jobs/same-job",
                            application_url="https://boards.greenhouse.io/acme/jobs/same-job",
                            title="Backend Engineer",
                            company="Acme",
                            location="Remote Spain",
                            description="Build APIs",
                            structured_data={"remote_policy": "remote", "regions": ["spain"]},
                            collected_at=datetime.now(UTC),
                        ),
                    ),
                    metrics=CollectionMetrics(provider_items=1, accepted_items=1),
                )

        service = PipelineCollectionService(
            lambda: Session(engine), collector_factory=lambda _snapshot: Collector()
        )
        snapshots = service.prepare(run_id)
        result = asyncio.run(service.execute(snapshots[0]))
        service.finalize(run_id, result)
        with Session(engine) as session:
            completed_run = session.get(JobSearchRun, run_id)
            assert completed_run is not None
            jobs = list(session.scalars(select(Job).join(JobSourceReference)))
            references = list(session.scalars(select(JobSourceReference)))
            run_jobs = list(session.scalars(select(RunJob).where(RunJob.run_id == run_id)))
            return {
                "snapshot": [
                    {**item, "source_id": item["source_key"]}
                    for item in (completed_run.source_snapshot_json or [])
                ],
                "calls": [
                    {
                        "source_id": call.source_key,
                        "source_type": call.source_type,
                        "name": call.name,
                        "configuration": dict(call.configuration),
                        "source_key": call.source_key,
                        "configuration_version": call.configuration_version,
                    }
                    for call in calls
                ],
                "metrics": (completed_run.source_results_json or {})[source_id][
                    "collection_metrics"
                ],
                "pool": len(jobs),
                "acquired": len(run_jobs),
                "references": [(ref.job_id, ref.source_id) for ref in references],
                "source_id": source_id,
            }

    broad = run_collection("broad.db", ["madrid", "spain", "europe"])
    restrictive = run_collection("restrictive.db", ["tokyo"])
    assert restrictive["snapshot"] == broad["snapshot"]
    assert restrictive["calls"] == broad["calls"]
    assert restrictive["metrics"] == broad["metrics"]
    assert broad["pool"] == 1
    assert broad["acquired"] == 3
    assert len(broad["references"]) == 1
    assert broad["references"][0][1] == broad["source_id"]
    assert restrictive["pool"] == 0
    assert restrictive["acquired"] == 0
    assert restrictive["references"] == []


def test_pipeline_blocks_acquisition_while_reprocessing_is_pending(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'barrier.db'}")
    Base.metadata.create_all(engine)
    fixtures = Path(__file__).parents[2] / "fixtures"
    with Session(engine) as session:
        data = json.loads((fixtures / "profile_seed.json").read_text())
        profile = ProfileRepository(session).create_v1(
            name=data["name"], profile_json=data["profile_json"]
        )
        run = RunService(session).create(reason="barrier", profile_id=profile.id)
        session.commit()
        run_id = run.id

    class PendingEligibility:
        async def process(self, _run_id: str) -> dict[str, object]:
            return {"complete": False, "pending": 1}

    calls: list[str] = []
    pipeline = Pipeline(
        get_session_factory(engine),
        provider=FakeLLMProvider(fixture=fixtures / "extraction_valid.json"),
    )
    cast(Any, pipeline)._eligibility = PendingEligibility()
    cast(Any, pipeline._collection).prepare = lambda *_args, **_kwargs: calls.append("acquired")
    result = asyncio.run(pipeline.run(run_id))
    assert result.error_code == "product_eligibility_reprocessing_pending"
    assert calls == []
