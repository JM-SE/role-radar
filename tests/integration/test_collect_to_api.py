"""Criterio de salida F2: MockTransport → DB → GET /jobs."""

import json
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.domain.enums import SourceType
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.collection_service import CollectionService


async def test_collect_to_review_api_and_second_run_does_not_duplicate(
    db_session: Session,
    client: httpx.AsyncClient,
    profile_bound_runs: tuple[str, RunRepository],
) -> None:
    profile_id, runs = profile_bound_runs
    payload = json.loads(
        (Path(__file__).parents[2] / "fixtures" / "greenhouse_jobs_sample.json").read_text()
    )
    payload["jobs"][0]["content"] = (
        "<p>This is a fully remote role. Build reliable APIs for Example Corp.</p>"
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
        service = CollectionService(
            db_session, runs=runs, collector=GreenhouseCollector(client=greenhouse_client)
        )
        first = await service.run_collect()
        db_session.commit()
        first_response = await client.get("/jobs")
        first_review_response = await client.get(
            "/jobs/location-unconfirmed", params={"profile_id": profile_id}
        )
        second = await service.run_collect()
        db_session.commit()
        second_response = await client.get("/jobs")
        second_review_response = await client.get(
            "/jobs/location-unconfirmed", params={"profile_id": profile_id}
        )

    assert first.status.value == "completed"
    assert first_response.status_code == 200
    assert first_response.json() == []
    assert first_review_response.status_code == 200
    first_reviews = first_review_response.json()
    assert len(first_reviews) == 1
    assert first_reviews[0]["title"] == "Backend Engineer"
    assert first_reviews[0]["company"] == "Example Corp"
    assert first_reviews[0]["reason_code"] == "region_unknown"
    assert second.status.value == "completed"
    assert second.stats_json is not None
    assert second.stats_json["new_jobs"] == 0
    assert second.stats_json["duplicates"] == 0
    assert second_response.json() == []
    second_reviews = second_review_response.json()
    assert len(second_reviews) == 1
    assert second_reviews[0]["id"] == first_reviews[0]["id"]
