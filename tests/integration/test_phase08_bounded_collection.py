"""File-backed finalize boundary: success is atomic and sanitised."""

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.db.base import Base
from role_radar.db.models import Job, JobSearchRun
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import SourceType
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.pipeline_collection import CollectionResult, PipelineCollectionService


def test_file_backed_finalize_persists_only_allowlisted_result(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'bounded.db'}")
    Base.metadata.create_all(engine)
    def factory() -> Session:
        return Session(engine)
    with Session(engine) as session:
        source = SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme", "company": "Acme"},
            enabled=True,
        )
        run = RunRepository(session).create_run("bounded")
        session.commit()
        source_id, run_id = source.id, run.id

    raw = RawJob(
        source="greenhouse",
        external_id="1",
        title="Engineer",
        company="Acme",
        source_url="https://boards.greenhouse.io/acme/jobs/1",
        application_url="https://boards.greenhouse.io/acme/jobs/1",
        description="Build APIs",
        structured_data={"id": "1"},
        collected_at=datetime.now(UTC),
    )
    outcome = CollectionSuccess(
        status="ok",
        jobs=(raw,),
        metrics=CollectionMetrics(provider_items=1, accepted_items=1, canonical_batch_bytes=1),
    )
    service = PipelineCollectionService(factory)
    service.finalize(run_id, CollectionResult(source_id, outcome))

    with Session(engine) as session:
        persisted = session.get(JobSearchRun, run_id)
        assert persisted is not None
        assert isinstance(persisted.source_results_json, dict)
        result = persisted.source_results_json[source_id]
        assert result["status"] == "ok"
        assert set(result) == {
            "status", "collected", "new_jobs", "duplicates", "prefiltered", "failed",
            "collection_metrics", "rejection_counts", "retryable", "http_status", "stop_code",
        }
        assert session.scalar(select(Job.id)) is not None
