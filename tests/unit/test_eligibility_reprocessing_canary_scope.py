import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from role_radar.db.base import Base
from role_radar.db.models import Job, JobSearchRun, RunJob
from role_radar.domain.enums import RunJobStage
from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.eligibility_reprocessing import (
    MANIFEST_KEY,
    POLICY_VERSION,
    EligibilityReprocessingService,
)
from role_radar.services.pipeline_extraction import PipelineExtractionService


class _Extraction:
    def __init__(self) -> None:
        self.prepared: list[str] = []
        self.executed: list[Any] = []
        self.finalized: list[Any] = []

    def prepare(self, job_id: str, *, corrective: bool = False) -> str:
        self.prepared.append(job_id)
        return job_id

    async def execute(self, prepared: Any) -> Any:
        self.executed.append(prepared)
        return prepared

    def finalize(self, result: Any) -> Any:
        self.finalized.append(result)
        return None


def _db(tmp_path: Path, *, canary: bool) -> tuple[Any, Any, str, list[str]]:
    engine = create_engine(f"sqlite:///{tmp_path / 'canary-scope.db'}")
    Base.metadata.create_all(engine)
    fixture = Path(__file__).parents[2] / "fixtures" / "profile_seed.json"
    with Session(engine) as session:
        data = json.loads(fixture.read_text())
        profile = ProfileRepository(session).create_v1(
            name="synthetic", profile_json=data["profile_json"]
        )
        run = RunRepository(session).create_run("synthetic", profile_id=profile.id)
        if canary:
            run.canary_budget_json = dict(CANARY_BUDGET)
            run.canary_checkpoint_json = {
                "version": 1,
                "stage": "discovery",
                "cursor": 0,
                "counts": {"broker_attempts": 1},
                "reservations": [],
                "logical_reservations": [],
            }
        jobs = [
            JobRepository(session).create(
                title=f"Old job {index}",
                company="Synthetic",
                description="Synthetic historical description",
                location="Remote",
            )
            for index in range(2)
        ]
        for job in jobs:
            job.created_at = datetime.now(UTC) - timedelta(days=30)
        run_id = run.id
        job_ids = [job.id for job in jobs]
        session.commit()
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(engine, class_=Session)
    return engine, factory, run_id, job_ids


def _process(factory: Any, run_id: str, extraction: _Extraction) -> dict[str, Any]:
    service = EligibilityReprocessingService(
        factory, cast(PipelineExtractionService, extraction)
    )
    return asyncio.run(service.process(run_id))


def test_fresh_canary_skips_old_corpus_and_resumes_empty_manifest(tmp_path: Path) -> None:
    engine, factory, run_id, job_ids = _db(tmp_path, canary=True)
    extraction = _Extraction()

    first = _process(factory, run_id, extraction)
    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None
        manifest = run.stats_json[MANIFEST_KEY]
        assert manifest["total"] == manifest["pending"] == manifest["completed"] == 0
        assert manifest["eligible"] == manifest["excluded"] == 0
        assert manifest["complete"] is True
        assert manifest["policy_version"] == POLICY_VERSION
        assert manifest["profile_binding"]["profile_id"] == run.profile_id
        assert manifest["cutoff_utc"]
        assert session.scalars(
            select(RunJob).where(
                RunJob.run_id == run_id, RunJob.stage == RunJobStage.PREFILTERED
            )
        ).all() == []
        checkpoint = run.canary_checkpoint_json
        assert checkpoint["counts"] == {"broker_attempts": 1}
        assert set(session.scalars(select(Job.id))) == set(job_ids)
    second = _process(factory, run_id, extraction)
    assert second == first
    assert extraction.prepared == extraction.executed == extraction.finalized == []
    assert len(job_ids) == 2


@pytest.mark.parametrize("mismatch", ["policy", "profile"])
def test_canary_fails_closed_on_frozen_manifest_binding_mismatch(
    tmp_path: Path, mismatch: str
) -> None:
    engine, factory, run_id, _job_ids = _db(tmp_path, canary=False)
    original = _process(factory, run_id, _Extraction())
    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None and run.stats_json is not None
        stats = dict(run.stats_json)
        manifest = dict(stats[MANIFEST_KEY])
        if mismatch == "policy":
            manifest["policy_version"] = "older-policy"
        else:
            manifest["profile_binding"] = dict(manifest["profile_binding"])
            manifest["profile_binding"]["row_version"] += 1
        stats[MANIFEST_KEY] = manifest
        run.stats_json = stats
        run.canary_budget_json = dict(CANARY_BUDGET)
        session.commit()

    with pytest.raises(RuntimeError, match="product_eligibility_manifest_mismatch"):
        _process(factory, run_id, _Extraction())
    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None
        assert run.stats_json[MANIFEST_KEY]["total"] == original["total"] == 2


def test_canary_does_not_rewrite_existing_nonempty_manifest_as_complete(tmp_path: Path) -> None:
    engine, factory, run_id, _job_ids = _db(tmp_path, canary=False)
    extraction = _Extraction()
    old_manifest = _process(factory, run_id, extraction)
    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None
        original = dict(run.stats_json[MANIFEST_KEY])
        run.canary_budget_json = dict(CANARY_BUDGET)
        session.commit()

    with pytest.raises(RuntimeError, match="product_eligibility_manifest_mismatch"):
        _process(factory, run_id, _Extraction())
    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None
        assert run.stats_json[MANIFEST_KEY] == original
        assert original["total"] == old_manifest["total"] == 2
