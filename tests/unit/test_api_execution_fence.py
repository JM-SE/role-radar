"""Tests for the HTTP producer fence middleware."""

from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager

import httpx
import pytest
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse

import role_radar.main as main


def _app(endpoint_events: list[str]) -> FastAPI:
    app = FastAPI()
    main.install_producer_fence_middleware(app)

    async def endpoint(request: Request) -> JSONResponse:
        endpoint_events.append(f"endpoint:{request.method}")
        return JSONResponse({"ok": True})

    app.add_api_route("/health", endpoint, methods=["GET", "HEAD", "OPTIONS"])
    app.add_api_route("/write", endpoint, methods=["POST"])
    return app


@pytest.mark.anyio
async def test_read_methods_leave_health_available_without_fence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint_events: list[str] = []
    app = _app(endpoint_events)
    guard_calls: list[str] = []

    @contextmanager
    def unexpected_guard() -> Iterator[None]:
        guard_calls.append("called")
        yield

    monkeypatch.setattr(main, "producer_guard", unexpected_guard)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        responses = [
            await client.request(method, "/health")
            for method in ("GET", "HEAD", "OPTIONS")
        ]

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert guard_calls == []
    assert endpoint_events == ["endpoint:GET", "endpoint:HEAD", "endpoint:OPTIONS"]


@pytest.mark.anyio
async def test_write_guard_survives_until_streaming_body_finishes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    app = FastAPI()

    @contextmanager
    def guard() -> Iterator[None]:
        events.append("enter")
        try:
            yield
        finally:
            events.append("exit")

    monkeypatch.setattr(main, "producer_guard", guard)
    main.install_producer_fence_middleware(app)

    async def stream() -> AsyncIterator[bytes]:
        events.append("body-start")
        yield b"ok"
        events.append("body-end")

    async def write(_request: Request) -> StreamingResponse:
        events.append("endpoint")
        return StreamingResponse(stream())

    app.add_api_route("/write", write, methods=["POST"])

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/write")

    assert response.status_code == 200
    assert response.content == b"ok"
    assert events == ["enter", "endpoint", "body-start", "body-end", "exit"]


@pytest.mark.anyio
async def test_fence_error_returns_sanitized_503_without_calling_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint_events: list[str] = []
    app = _app(endpoint_events)

    @contextmanager
    def blocked_guard() -> Iterator[None]:
        raise main.FenceError()
        yield

    monkeypatch.setattr(main, "producer_guard", blocked_guard)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/write")

    assert response.status_code == 503
    assert response.json() == {"detail": "service unavailable"}
    assert endpoint_events == []
