"""Offline fixed-origin HTTP, retry, bounds and lifecycle matrix."""

import asyncio
import gzip
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from role_radar.collectors.bounded_http import (
    BoundedHttpClient,
    BoundedHttpError,
    BoundedHttpResponse,
)
from role_radar.collectors.outcomes import CollectorFailureCode
from role_radar.collectors.policy import CollectionRunBudget, HttpPolicy


class RawStream(httpx.AsyncByteStream):
    def __init__(self, value: bytes) -> None:
        self.value = value

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.value

    async def aclose(self) -> None:
        return None


class Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def _policy(**kwargs: Any) -> HttpPolicy:
    return HttpPolicy(
        origin="https://boards-api.greenhouse.io",
        allowed_path_prefix="/v1/boards/",
        allowed_query_keys=frozenset({"content"}),
        **kwargs,
    )


async def _get(
    handler: httpx.MockTransport,
    *,
    policy: HttpPolicy | None = None,
    clock: Clock | None = None,
    sleeper: object = asyncio.sleep,
    budget: CollectionRunBudget | None = None,
) -> BoundedHttpResponse:
    async with BoundedHttpClient(
        policy or _policy(),
        transport=handler,
        clock=clock or Clock(),
        sleeper=sleeper,  # type: ignore[arg-type]
        budget=budget,
    ) as client:
        return await client.get("/v1/boards/acme/jobs", query=(("content", "true"),))


def test_fixed_origin_query_and_redirect_are_enforced() -> None:
    seen: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "/elsewhere"})

    async def run() -> None:
        with pytest.raises(BoundedHttpError) as error:
            await _get(httpx.MockTransport(handler))
        assert error.value.code is CollectorFailureCode.REDIRECT
        assert len(seen) == 1
        assert str(seen[0].url) == (
            "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true"
        )

    asyncio.run(run())


def test_status_retry_uses_deterministic_backoff_and_budget() -> None:
    calls = 0
    sleeps: list[float] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503) if calls < 3 else httpx.Response(200, json={"ok": True})

    async def sleep(value: float) -> None:
        sleeps.append(value)

    async def run() -> None:
        result = await _get(httpx.MockTransport(handler), sleeper=sleep)
        assert result.metrics.wire_attempts == 3
        assert result.metrics.retries == 2
        assert sleeps == [1.0, 2.0]

    asyncio.run(run())


def test_response_wire_and_decoded_caps_and_gzip_are_stream_bounded() -> None:
    async def run() -> None:
        exact = b"x" * (8 * 1024 * 1024)

        async def exact_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=exact, headers={"content-type": "application/json"})

        result = await _get(httpx.MockTransport(exact_handler))
        assert result.metrics.wire_bytes == len(exact)

        async def over_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=exact + b"x",
                headers={"content-type": "application/json"},
            )

        with pytest.raises(BoundedHttpError) as over:
            await _get(httpx.MockTransport(over_handler))
        assert over.value.code is CollectorFailureCode.RESPONSE_TOO_LARGE

        compressed = gzip.compress(b"{}")

        async def gzip_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                stream=RawStream(compressed),
                headers={"content-type": "application/json", "content-encoding": "gzip"},
            )

        gzip_result = await _get(httpx.MockTransport(gzip_handler))
        assert gzip_result.body == b"{}"

    asyncio.run(run())


def test_budget_blocks_attempt_101_without_transport() -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"ok": True})

    async def run() -> None:
        budget = CollectionRunBudget(0)
        with pytest.raises(BoundedHttpError) as error:
            await _get(httpx.MockTransport(handler), budget=budget)
        assert error.value.code is CollectorFailureCode.REQUEST_BUDGET
        assert calls == 0

    asyncio.run(run())
