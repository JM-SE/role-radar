"""Criterio de salida F2: MockTransport → DB → GET /jobs."""

import json
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.domain.enums import SourceType
from role_radar.repositories.sources import SourceRepository
from role_radar.services.collection_service import CollectionService


async def test_collect_to_api_and_second_run_does_not_duplicate(
    db_session: Session, client: httpx.AsyncClient
) -> None:
    payload = json.loads(
        (Path(__file__).parents[2] / "fixtures" / "greenhouse_jobs_sample.json").read_text()
    )

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    SourceRepository(db_session).create(
        type=SourceType.GREENHOUSE,
        name="Example Corp Greenhouse",
        configuration={"board_token": "example", "company": "Example Corp"},
        enabled=True,
    )
    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as greenhouse_client:
        collector = GreenhouseCollector(client=greenhouse_client)
        first = await CollectionService(db_session, collector=collector).run_collect()
        db_session.commit()
        first_response = await client.get("/jobs")
        second = await CollectionService(db_session, collector=collector).run_collect()
        db_session.commit()
        second_response = await client.get("/jobs")

    assert first.status.value == "completed"
    assert first_response.status_code == 200
    assert first_response.json()[0]["title"] == "Backend Engineer"
    assert first_response.json()[0]["company"] == "Example Corp"
    assert second.status.value == "completed"
    assert second.stats_json is not None
    assert second.stats_json["duplicates"] == 1
    assert len(second_response.json()) == 1
