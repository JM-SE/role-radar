"""File-backed finalize boundary: success is atomic and sanitised."""

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.db.base import Base
from role_radar.db.models import Job, JobSearchRun
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import SourceType
from role_radar.domain.profile import CandidateProfileV1
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.pipeline_collection import CollectionResult, PipelineCollectionService


def test_file_backed_finalize_persists_only_allowlisted_result(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'bounded.db'}")
    Base.metadata.create_all(engine)

    def factory() -> Session:
        return Session(engine)

    with Session(engine) as session:
        profile_data = json.loads(
            (Path(__file__).parents[2] / "fixtures" / "profile_seed.json").read_text()
        )
        profile_data["profile_json"] = CandidateProfileV1.model_validate(
            profile_data["profile_json"]
        ).model_copy(
            update={
                "target_roles": ("frontend",),
                "target_titles": (),
                "regions": ("argentina",),
                "hard_constraints": CandidateProfileV1.model_validate(
                    profile_data["profile_json"]
                ).hard_constraints.model_copy(
                    update={"available_work_authorizations": ("argentina",)}
                ),
            }
        ).model_dump(mode="json")
        profile = ProfileRepository(session).create_v1(
            name=profile_data["name"], profile_json=profile_data["profile_json"]
        )
        source = SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme", "company": "Acme"},
            enabled=True,
        )
        run = RunRepository(session).create_run("bounded", profile_id=profile.id)
        session.commit()
        source_id, run_id = source.id, run.id

    raw = RawJob(
        source="greenhouse",
        external_id="1",
        title="Senior Frontend Engineer",
        company="Acme",
        location="Remote",
        source_url="https://boards.greenhouse.io/acme/jobs/1",
        application_url="https://boards.greenhouse.io/acme/jobs/1",
        description="Fully remote position. Work remotely from Argentina.",
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
            "status",
            "collected",
            "new_jobs",
            "duplicates",
            "prefiltered",
            "profile_rejected",
            "profile_reason_counts",
            "clarification_attempts",
            "failed",
            "collection_metrics",
            "rejection_counts",
            "retryable",
            "http_status",
            "stop_code",
        }
        assert result["new_jobs"] == 1
        assert result["profile_rejected"] == 0
        assert session.scalar(select(Job.id)) is not None
