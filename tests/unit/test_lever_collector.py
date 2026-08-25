import httpx

from role_radar.collectors.lever import LeverCollector
from role_radar.collectors.outcomes import CollectionFailure, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot


def _item(identifier: int, *, host: str = "jobs.lever.co") -> dict[str, object]:
    return {
        "id": str(identifier),
        "text": f"Engineer {identifier}",
        "categories": {"location": "Remote"},
        "descriptionPlain": "Build APIs",
        "hostedUrl": f"https://{host}/acme/{identifier}",
        "applyUrl": f"https://{host}/acme/{identifier}/apply",
        "candidate": {"email": "canary@example.test"},
    }


def _snapshot(region: str = "global") -> SourceSnapshot:
    return SourceSnapshot("source-1", "lever", "Acme", {"site": "acme", "region": region})


async def test_short_page_maps_allowlisted_fields_and_never_calls_detail_api() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(
            200,
            json=[_item(1)],
            headers={"content-type": "application/json"},
        )

    outcome = await LeverCollector(transport=httpx.MockTransport(handler)).collect(
        _snapshot(), CollectorRuntime()
    )

    assert isinstance(outcome, CollectionSuccess)
    assert len(outcome.jobs) == 1
    assert outcome.jobs[0].company == "Acme"
    assert outcome.jobs[0].application_url is not None
    assert outcome.jobs[0].application_url.endswith("/apply")
    assert "candidate" not in outcome.jobs[0].structured_data
    assert calls == ["https://api.lever.co/v0/postings/acme?mode=json&limit=100&skip=0"]


async def test_five_full_pages_use_one_empty_sentinel_and_no_seventh_request() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        calls.append((params["limit"], params["skip"]))
        skip = int(params["skip"])
        payload = [] if skip == 500 else [_item(index) for index in range(skip, skip + 100)]
        return httpx.Response(200, json=payload, headers={"content-type": "application/json"})

    outcome = await LeverCollector(transport=httpx.MockTransport(handler)).collect(
        _snapshot(), CollectorRuntime()
    )

    assert isinstance(outcome, CollectionSuccess)
    assert outcome.metrics.provider_items == 500
    assert outcome.metrics.overflow_probe_items == 0
    assert outcome.metrics.logical_pages == 6
    assert len(calls) == 6
    assert calls[-1] == ("1", "500")


async def test_overflow_sentinel_is_atomic_and_not_mapped() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        calls.append((params["limit"], params["skip"]))
        skip = int(params["skip"])
        payload = (
            [_item(999)] if skip == 500 else [_item(index) for index in range(skip, skip + 100)]
        )
        return httpx.Response(200, json=payload, headers={"content-type": "application/json"})

    outcome = await LeverCollector(transport=httpx.MockTransport(handler)).collect(
        _snapshot(), CollectorRuntime()
    )

    assert isinstance(outcome, CollectionFailure)
    assert outcome.error_code.value == "job_limit"
    assert outcome.metrics.provider_items == 500
    assert outcome.metrics.overflow_probe_items == 1
    assert outcome.metrics.accepted_items == 0
    assert len(calls) == 6
    assert all(int(skip) <= 500 for _, skip in calls)


async def test_eu_never_uses_global_origin_or_host() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(
            200,
            json=[_item(1, host="jobs.eu.lever.co")],
            headers={"content-type": "application/json"},
        )

    outcome = await LeverCollector(transport=httpx.MockTransport(handler)).collect(
        _snapshot("eu"), CollectorRuntime()
    )
    assert isinstance(outcome, CollectionSuccess)
    assert seen == ["https://api.eu.lever.co/v0/postings/acme?mode=json&limit=100&skip=0"]
