import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from role_radar.broker.fake import FakeLLMProvider
from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.db.base import Base
from role_radar.db.models import JobSearchRun, RunJob
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus, SourceType
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.eligibility_reprocessing import (
    MANIFEST_KEY,
    EligibilityReprocessingService,
)
from role_radar.services.pipeline_extraction import PipelineExtractionService
from role_radar.worker.checkpoints import recompute_stats
from role_radar.worker.pipeline import Pipeline


def _db(tmp_path: Path) -> tuple[Engine, sessionmaker[Session], str, list[str]]:
    engine = create_engine(f"sqlite:///{tmp_path / 'reprocess.db'}")
    Base.metadata.create_all(engine)
    data = json.loads(
        (Path(__file__).parents[2] / "fixtures" / "profile_seed.json").read_text()
    )
    with Session(engine) as session:
        profile = ProfileRepository(session).create_v1(
            name="test", profile_json=data["profile_json"]
        )
        run = RunRepository(session).create_run("reprocess", profile_id=profile.id)
        jobs = [JobRepository(session).create(
            title=f"Job {i}", company="Acme", description="Build APIs", location="Remote"
        ) for i in range(2)]
        for i, job in enumerate(jobs):
            job.created_at = datetime.now(UTC) - timedelta(minutes=2 - i)
        ids = [job.id for job in jobs]
        run_id = run.id
        session.commit()
    factory = cast(sessionmaker[Session], lambda: Session(engine))
    return engine, factory, run_id, ids


class _Extraction:
    def __init__(self, fail_id: str | None = None) -> None:
        self.prepared: list[str] = []
        self.fail_id = fail_id

    def prepare(self, job_id: str, *, corrective: bool = False) -> None:
        self.prepared.append(job_id)
        if job_id == self.fail_id:
            raise RuntimeError("extraction_failed")
        return None


async def _process(
    factory: sessionmaker[Session], run_id: str, extraction: _Extraction
) -> dict[str, Any]:
    service = EligibilityReprocessingService(
        factory, cast(PipelineExtractionService, extraction)
    )
    return await service.process(run_id)


def test_reprocessing_manifest_is_write_once_and_traversal_is_deterministic(tmp_path: Path) -> None:
    engine, factory, run_id, ids = _db(tmp_path)
    extraction = _Extraction()
    first = asyncio.run(_process(factory, run_id, extraction))
    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None
        assert run.stats_json is not None
        manifest = run.stats_json[MANIFEST_KEY]
        assert manifest["cutoff_utc"] == first["cutoff_utc"]
        assert manifest["policy_version"]
        assert manifest["profile_binding"]["profile_id"] == run.profile_id
        rows = list(
            session.scalars(
                select(RunJob)
                .where(RunJob.run_id == run_id)
                .order_by(RunJob.created_at, RunJob.job_id)
            )
        )
        assert {row.job_id for row in rows} == set(ids)
        assert extraction.prepared == [row.job_id for row in rows]
    second = asyncio.run(_process(factory, run_id, extraction))
    assert second["cutoff_utc"] == first["cutoff_utc"]
    assert extraction.prepared == ids


def test_reprocessing_resumes_valid_checkpoints_and_records_extraction_failure(
    tmp_path: Path,
) -> None:
    _engine, factory, run_id, ids = _db(tmp_path)
    extraction = _Extraction(fail_id=ids[1])
    result = asyncio.run(_process(factory, run_id, extraction))
    assert result["pending"] == 0 and result["complete"] is True
    assert result["excluded"] >= 1 and result["reason_counts"]
    retry = _Extraction()
    resumed = asyncio.run(_process(factory, run_id, retry))
    assert resumed["complete"] is True
    assert retry.prepared == []


def test_current_and_new_jobs_share_feedback_eligibility_reasons(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'parity.db'}")
    Base.metadata.create_all(engine)
    fixtures = Path(__file__).parents[2] / "fixtures"
    with Session(engine) as session:
        data = json.loads((fixtures / "profile_seed.json").read_text())
        profile = ProfileRepository(session).create_v1(
            name="test", profile_json=data["profile_json"]
        )
        source = SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme", "company": "Acme"},
        )
        current = JobRepository(session).create(
            title="Backend Engineer", company="Acme", description="Build APIs", location="Remote"
        )
        run = RunRepository(session).create_run("parity", profile_id=profile.id)
        session.commit()
        run_id, source_id, current_id = run.id, source.id, current.id

    class Collector:
        async def collect(
            self, _snapshot: SourceSnapshot, _runtime: CollectorRuntime
        ) -> CollectionSuccess:
            return CollectionSuccess(
                status="ok",
                jobs=(RawJob(
                    source="greenhouse", external_id="new-job",
                    source_url="https://boards.greenhouse.io/acme/jobs/new-job",
                    application_url="https://boards.greenhouse.io/acme/jobs/new-job",
                    title="Platform Engineer",
                    company="Other",
                    description="Build APIs for platform",
                    collected_at=datetime.now(UTC),
                ),),
                metrics=CollectionMetrics(provider_items=1, accepted_items=1),
            )

    pipeline = Pipeline(
        lambda: Session(engine),
        provider=FakeLLMProvider(fixture=fixtures / "extraction_valid.json"),
        collector_factory=lambda _snapshot: Collector(),
    )
    asyncio.run(pipeline.run(run_id))
    with Session(engine) as session:
        completed = session.get(JobSearchRun, run_id)
        assert completed is not None
        assert completed.status is JobSearchRunStatus.COMPLETED
        rows = list(session.scalars(select(RunJob).where(RunJob.run_id == run_id)))
        current_row = next(
            row
            for row in rows
            if row.job_id == current_id and row.stage is RunJobStage.PREFILTERED
        )
        current_outcome = current_row.outcome_json
        if current_outcome is None:
            raise AssertionError("current checkpoint has no outcome")
        current_decision = current_outcome["decision"]
        new_decisions = [
            row.outcome_json["feedback_eligibility"]
            for row in rows
            if row.job_id != current_id
            and row.stage is RunJobStage.SCORED
            and row.status is RunJobStatus.SUCCEEDED
            and row.outcome_json
            and "feedback_eligibility" in row.outcome_json
        ]
        assert len(new_decisions) == 1
        assert new_decisions[0]["profile_binding"] == current_decision["profile_binding"]
        assert new_decisions[0]["eligible"] == current_decision["eligible"]
        assert new_decisions[0]["reason_codes"] == current_decision["reason_codes"]
        assert source_id in (completed.source_results_json or {})


def test_feedback_reprocessing_stats_are_preserved_and_not_source_prefiltered() -> None:
    row = RunJob(
        run_id="run",
        job_id="job",
        stage=RunJobStage.PREFILTERED,
        status=RunJobStatus.SUCCEEDED,
        outcome_json={"purpose": "feedback_eligibility_reprocess"},
    )
    manifest = {"complete": True, "pending": 0, "completed": 1}
    stats = recompute_stats({}, [row], {MANIFEST_KEY: manifest})
    assert stats[MANIFEST_KEY] == manifest
    assert stats["prefiltered"] == 0
