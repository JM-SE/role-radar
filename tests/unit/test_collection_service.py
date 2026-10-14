"""Pruebas de orquestación del servicio de colección."""

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from role_radar.collectors.protocols import CollectionContext
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobSearchRunStatus, SourceType
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.collection_service import CollectionService


class FakeCollector:
    def __init__(self, jobs: list[RawJob]) -> None:
        self.jobs = jobs

    async def collect(self, context: CollectionContext) -> list[RawJob]:
        return self.jobs


async def test_collection_service_persists_and_counts(db_session: Session) -> None:
    profile_data = json.loads(
        (Path(__file__).parents[2] / "fixtures" / "profile_seed.json").read_text()
    )
    profile = ProfileRepository(db_session).create_v1(
        name=profile_data["name"], profile_json=profile_data["profile_json"]
    )
    db_session.commit()
    SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE,
        name="Acme board",
        configuration={"board_token": "acme", "company": "Acme"},
        enabled=True,
    )
    service = CollectionService(
        db_session,
        collector=FakeCollector(
            [
                RawJob(
                    source="greenhouse",
                    external_id="1",
                    source_url="https://example.test/jobs/1",
                    title="Gardener",
                    company="Acme",
                    location="Remote Spain",
                    description="<p>Garden work</p>",
                    structured_data={"remote_policy": "remote", "regions": ["spain"]},
                    collected_at=datetime.now(UTC),
                ),
                RawJob(
                    source="greenhouse",
                    external_id="2",
                    title="Incomplete",
                    company="Acme",
                    description=None,
                    collected_at=datetime.now(UTC),
                ),
            ]
        ),
    )
    run = await service.run_collect(profile_id=profile.id)
    db_session.commit()
    assert run.status == JobSearchRunStatus.COMPLETED
    assert run.stats_json == {
        "collected": 2,
        "new_jobs": 0,
        "duplicates": 0,
        "prefiltered": 1,
        "profile_rejected": 1,
        "failed": 0,
        "sources_ok": 1,
        "sources_failed": 0,
    }
