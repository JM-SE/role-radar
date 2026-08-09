"""Small bounded transport shared by search adapters.

The transport owns the client and never exposes response headers or bodies to
callers.  Adapters receive only a bounded byte document to map immediately.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, cast

import httpx

from role_radar.discovery.contracts import SearchRequest

MAX_SEARCH_BODY_BYTES = 1 * 1024 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 20_000


class SearchHttpError(Exception):
    """Stable transport error without provider payload, URL, or query."""

    def __init__(self, code: str, *, status_code: int | None = None) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SearchHttpResponse:
    status_code: int
    body: bytes


class BoundedSearchHttpClient:
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> BoundedSearchHttpClient:
        self._client = httpx.AsyncClient(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=5.0, read=20.0, write=5.0, pool=5.0),
            limits=httpx.Limits(
                max_connections=1, max_keepalive_connections=1, keepalive_expiry=30.0
            ),
            transport=self._transport,
        )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        request: SearchRequest,
        *,
        headers: dict[str, str],
        params: list[tuple[str, str]] | None = None,
        json: dict[str, Any] | None = None,
    ) -> SearchHttpResponse:
        client = self._client
        if client is None:
            raise RuntimeError("search HTTP client is not open")
        if method not in {"GET", "POST"}:
            raise SearchHttpError("method_not_allowed")
        try:
            async with asyncio.timeout(request.deadline_seconds):
                async with client.stream(
                    method, url, params=cast(Any, params or []), json=json, headers=headers
                ) as response:
                    if response.status_code < 300:
                        self._validate_content_type(response.headers.get("content-type", ""))
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_SEARCH_BODY_BYTES:
                            raise SearchHttpError(
                                "response_too_large", status_code=response.status_code
                            )
                        chunks.append(chunk)
                    return SearchHttpResponse(response.status_code, b"".join(chunks))
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            raise SearchHttpError("timeout") from exc
        except SearchHttpError:
            raise
        except httpx.HTTPError as exc:
            raise SearchHttpError("network") from exc

    @staticmethod
    def _validate_content_type(value: str) -> None:
        media = value.split(";", 1)[0].strip().lower()
        if media != "application/json" and not (
            media.startswith("application/") and media.endswith("+json")
        ):
            raise SearchHttpError("content_type")
