"""Greenhouse protocol, single request and item outcome semantics."""

import asyncio

import httpx

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionSuccess,
    CollectorFailureCode,
)
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot


def _snapshot() -> SourceSnapshot:
    return SourceSnapshot(
        source_id="source-1",
        source_type="greenhouse",
        name="Acme",
        configuration={"board_token": "acme", "company": "Acme"},
        configuration_version=1,
    )


def _item(identifier: int, *, title: str = "Engineer") -> dict[str, object]:
    return {
        "id": identifier,
        "title": title,
        "absolute_url": f"https://boards.greenhouse.io/acme/jobs/{identifier}",
        "content": "Build APIs",
    }


def test_greenhouse_has_one_content_true_request_and_no_details() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"jobs": [_item(1)]})

    async def run() -> None:
        collector = GreenhouseCollector(transport=httpx.MockTransport(handler))
        outcome = await collector.collect(_snapshot(), CollectorRuntime())
        assert isinstance(outcome, CollectionSuccess)
        assert len(outcome.jobs) == 1
        assert len(requests) == 1
        assert requests[0].url.path == "/v1/boards/acme/jobs"
        assert str(requests[0].url.params) == "content=true"

    asyncio.run(run())


def test_greenhouse_empty_mixed_duplicates_and_all_invalid() -> None:
    payloads: list[dict[str, object]] = [
        {"jobs": []},
        {"jobs": [_item(1), {"title": "missing id"}]},
        {"jobs": [_item(1), _item(1), _item(1, title="Conflict")]},
        {"jobs": [{"title": "missing id"}, "not an item"]},
    ]

    async def run() -> None:
        for payload in payloads:
            async def handler(
                _request: httpx.Request, payload: dict[str, object] = payload
            ) -> httpx.Response:
                return httpx.Response(200, json=payload)

            collector = GreenhouseCollector(transport=httpx.MockTransport(handler))
            outcome = await collector.collect(_snapshot(), CollectorRuntime())
            jobs = payload["jobs"]
            assert isinstance(jobs, list)
            if jobs == []:
                assert isinstance(outcome, CollectionSuccess)
                assert outcome.status == "ok"
            elif jobs == [_item(1), {"title": "missing id"}]:
                assert isinstance(outcome, CollectionSuccess)
                assert outcome.status == "partial"
                assert outcome.rejection_counts.invalid_item == 1
            elif len(jobs) == 3:
                assert isinstance(outcome, CollectionSuccess)
                assert outcome.rejection_counts.duplicate_identical == 1
                assert outcome.rejection_counts.duplicate_conflict == 1
            else:
                assert isinstance(outcome, CollectionFailure)
                assert outcome.error_code is CollectorFailureCode.NO_VALID_ITEMS

    asyncio.run(run())


def test_greenhouse_501_items_fails_atomically() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jobs": [_item(index) for index in range(501)]})

    async def run() -> None:
        outcome = await GreenhouseCollector(
            transport=httpx.MockTransport(handler)
        ).collect(_snapshot(), CollectorRuntime())
        assert isinstance(outcome, CollectionFailure)
        assert outcome.error_code is CollectorFailureCode.JOB_LIMIT
        assert outcome.metrics.accepted_items == 0

    asyncio.run(run())
