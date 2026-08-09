"""Brave Search adapter: fixed GET origin and transient URL/rank mapping."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

import httpx

from role_radar.collectors.bounded_json import BoundedJsonError, ensure_object, loads_bounded
from role_radar.discovery.contracts import (
    ProviderTier,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
)
from role_radar.discovery.providers.bounded_http import (
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    BoundedSearchHttpClient,
    SearchHttpError,
)

BRAVE_ORIGIN = "https://api.search.brave.com"
BRAVE_PATH = "/res/v1/web/search"


class BraveSearchProvider:
    provider = "brave"
    tier = "free"

    def __init__(self, api_key: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        if not api_key:
            raise ValueError("Brave credential is required")
        self._api_key = api_key
        self._transport = transport
        self._client: BoundedSearchHttpClient | None = None

    async def __aenter__(self) -> BraveSearchProvider:
        self._client = await BoundedSearchHttpClient(transport=self._transport).__aenter__()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def search(self, request: SearchRequest) -> SearchResponse:
        started = time.monotonic()
        client = self._client
        if client is None:
            raise RuntimeError("Brave provider is not open")
        try:
            result = await client.request(
                "GET",
                BRAVE_ORIGIN + BRAVE_PATH,
                request,
                headers={
                    "Accept": "application/json",
                    "X-Subscription-Token": self._api_key,
                },
                params=[
                    ("q", request.query),
                    ("count", str(request.max_results)),
                    ("safesearch", "moderate"),
                ],
            )
            if not 200 <= result.status_code < 300:
                return _failure(result.status_code, started)
            payload = loads_bounded(result.body, max_depth=MAX_JSON_DEPTH, max_nodes=MAX_JSON_NODES)
            hits = _map_results(ensure_object(payload).get("web"))
            return SearchResponse(
                provider="brave",
                tier=ProviderTier.FREE,
                status="succeeded" if hits else "empty",
                hits=tuple(hits),
                result_count=len(hits),
                duration_ms=_duration(started),
            )
        except (BoundedJsonError, TypeError, ValueError):
            return _bad("malformed", started)
        except SearchHttpError as exc:
            return _bad(exc.code, started)


def _map_results(value: Any) -> list[TransientSearchHit]:
    if value is None:
        return []
    if not isinstance(value, Mapping):
        raise TypeError("web object required")
    results = value.get("results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise TypeError("results list required")
    hits: list[TransientSearchHit] = []
    for index, item in enumerate(results[:10], start=1):
        if not isinstance(item, Mapping) or not isinstance(item.get("url"), str):
            raise TypeError("result URL required")
        hits.append(TransientSearchHit(url=item["url"], rank=index))
    return hits


def _duration(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _failure(status: int, started: float) -> SearchResponse:
    code = "rate_limited" if status == 429 else "upstream" if status >= 500 else "http_status"
    return _bad(code, started, status=status)


def _bad(code: str, started: float, *, status: int | None = None) -> SearchResponse:
    del status
    return SearchResponse(
        provider="brave",
        tier=ProviderTier.FREE,
        status="failed" if code != "malformed" else "malformed",
        error_code=code,
        duration_ms=_duration(started),
    )
