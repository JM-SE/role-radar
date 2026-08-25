import asyncio

import httpx

from role_radar.collectors.jobicy import JobicyCollector
from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionSuccess,
    CollectorFailureCode,
)
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot


def _snapshot() -> SourceSnapshot:
    return SourceSnapshot(
        source_id="jobicy-source",
        source_type="jobicy",
        name="Jobicy LATAM",
        configuration={"region": "latam", "remote_only": True},
        source_key="jobicy:latam",
        configuration_version=1,
    )


def _job(identifier: int, *, canary: str | None = None) -> dict[str, object]:
    item: dict[str, object] = {
        "id": identifier,
        "url": f"https://jobicy.com/jobs/{identifier}",
        "jobTitle": "Backend Engineer",
        "companyName": "Acme",
        "jobGeo": "LATAM",
        "jobDescription": "<p>Build APIs</p>",
        "pubDate": "2026-08-09T12:00:00Z",
    }
    if canary is not None:
        item[canary] = "must not be persisted"
    return item


def test_jobicy_fixed_latam_request_and_allowlisted_mapping() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"jobs": [_job(7, canary="unknownField")]})

    async def run() -> None:
        outcome = await JobicyCollector(transport=httpx.MockTransport(handler)).collect(
            _snapshot(), CollectorRuntime()
        )
        assert isinstance(outcome, CollectionSuccess)
        assert outcome.status == "ok"
        assert outcome.jobs[0].external_id == "7"
        assert outcome.jobs[0].source_url == "https://jobicy.com/jobs/7"
        assert outcome.jobs[0].application_url == "https://jobicy.com/jobs/7"
        assert "unknownField" not in outcome.jobs[0].structured_data
        assert len(requests) == 1
        assert requests[0].url.path == "/api/v2/remote-jobs"
        assert str(requests[0].url.params) == "count=100&geo=latam"

    asyncio.run(run())


def test_jobicy_empty_mixed_and_all_invalid_are_atomic() -> None:
    payloads: list[dict[str, object]] = [
        {"jobs": []},
        {"jobs": [_job(1), {"id": 2}]},
        {"jobs": [{"id": 2}]},
    ]

    async def run() -> None:
        for payload in payloads:
            current_payload = payload

            async def handler(
                _request: httpx.Request, payload: dict[str, object] = current_payload
            ) -> httpx.Response:
                return httpx.Response(200, json=payload)

            outcome = await JobicyCollector(transport=httpx.MockTransport(handler)).collect(
                _snapshot(), CollectorRuntime()
            )
            if payload["jobs"] == []:
                assert isinstance(outcome, CollectionSuccess)
                assert outcome.status == "ok"
            elif isinstance(outcome, CollectionSuccess) and outcome.jobs:
                assert isinstance(outcome, CollectionSuccess)
                assert outcome.status == "partial"
            else:
                assert isinstance(outcome, CollectionFailure)
                assert outcome.error_code is CollectorFailureCode.NO_VALID_ITEMS

    asyncio.run(run())


def test_jobicy_does_not_retry_wire_attempts() -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"jobs": []})

    async def run() -> None:
        outcome = await JobicyCollector(transport=httpx.MockTransport(handler)).collect(
            _snapshot(), CollectorRuntime()
        )
        assert isinstance(outcome, CollectionFailure)
        assert outcome.error_code is CollectorFailureCode.UPSTREAM
        assert calls == 1

    asyncio.run(run())
