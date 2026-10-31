"""Pruebas de orquestación del servicio de colección."""

from datetime import UTC, datetime

import httpx
from sqlalchemy.orm import Session

from role_radar.collectors.protocols import CollectionContext
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobSearchRunStatus, SourceType
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.collection_service import CollectionService


class FakeCollector:
    def __init__(self, jobs: list[RawJob]) -> None:
        self.jobs = jobs

    async def collect(self, context: CollectionContext) -> list[RawJob]:
        return self.jobs


async def test_collection_service_persists_review_only_and_counts(
    db_session: Session,
    client: httpx.AsyncClient,
    profile_bound_runs: tuple[str, RunRepository],
) -> None:
    profile_id, runs = profile_bound_runs
    SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE,
        name="Acme board",
        configuration={"board_token": "acme", "company": "Acme"},
        enabled=True,
    )
    service = CollectionService(
        db_session,
        runs=runs,
        collector=FakeCollector(
            [
                RawJob(
                    source="greenhouse",
                    external_id="1",
                    source_url="https://boards.greenhouse.io/acme/jobs/1",
                    title="Backend Engineer",
                    company="Acme",
                    location="Remote",
                    description="Fully remote role. Build APIs.",
                    structured_data={"remote_policy": "remote"},
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
    run = await service.run_collect()
    db_session.commit()
    assert run.status == JobSearchRunStatus.COMPLETED
    assert run.stats_json == {
        "collected": 2,
        "new_jobs": 0,
        "duplicates": 0,
        "prefiltered": 1,
        "failed": 0,
        "sources_ok": 1,
        "sources_failed": 0,
    }
    review_response = await client.get(
        "/jobs/location-unconfirmed", params={"profile_id": profile_id}
    )
    assert review_response.status_code == 200
    reviews = review_response.json()
    assert len(reviews) == 1
    assert reviews[0]["external_id"] == "1"
    assert reviews[0]["reason_code"] == "region_unknown"
    assert (await client.get("/jobs")).json() == []
