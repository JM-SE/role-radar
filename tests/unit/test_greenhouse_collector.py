"""Pruebas offline del collector Greenhouse."""

import json
from pathlib import Path

import httpx

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.protocols import CollectionContext


def test_greenhouse_collector_maps_fixture() -> None:
    payload = json.loads(
        (Path(__file__).parents[2] / "fixtures" / "greenhouse_jobs_sample.json").read_text()
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"] == "application/json"
        return httpx.Response(200, json=payload)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            collector = GreenhouseCollector(client=client, timeout=2, user_agent="test")
            jobs = await collector.collect(
                CollectionContext(
                    source_id="source-1",
                    board_token="example",
                    company="Example Corp",
                    source_name="Example Corp Greenhouse",
                )
            )
        assert len(jobs) == 1
        assert jobs[0].external_id == "101"
        assert jobs[0].title == "Backend Engineer"
        assert jobs[0].company == "Example Corp"

    import asyncio

    asyncio.run(run())
