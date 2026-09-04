"""Unavailable-by-default, exact-host real ATS transport boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from math import isfinite
from time import monotonic
from typing import Final, cast

import httpx

from role_radar.collectors.policy import GREENHOUSE_POLICY, LEVER_POLICY

from .r2_real_ats_capability import (
    REAL_ATS_HOSTS,
    ApprovedRealATSCapability,
    RealATSCapabilityError,
)

_TOKEN = object()
_TEST_TOKEN = object()
_CREDENTIAL_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "proxy-authenticate",
        "set-cookie",
        "www-authenticate",
        "api-key",
        "x-access-token",
        "x-client-secret",
        "x-password",
        "x-secret",
        "x-api-key",
        "x-auth-token",
    }
)
_MAX_LEVER_SKIP = 500
_MAX_LEVER_LIMIT = 100
REAL_ATS_WIRE_LIMIT_BYTES: Final[int] = max(
    GREENHOUSE_POLICY.http.wire_limit_bytes, LEVER_POLICY.http.wire_limit_bytes
)
_Route = tuple[str, str, str]


class RealATSTransportError(ValueError):
    def __init__(self, code: str = "real_ats_transport_rejected") -> None:
        self.code = code if code.startswith("real_ats_") else "real_ats_transport_rejected"
        super().__init__(self.code)


def _routes_from_source_configs(configs: tuple[Mapping[str, object], ...]) -> tuple[_Route, ...]:
    routes: list[_Route] = []
    try:
        for item in configs:
            family = item["family"]
            configuration = cast(Mapping[str, object], item["configuration"])
            if family == "greenhouse":
                board_token = configuration["board_token"]
                if type(board_token) is not str or not board_token:
                    raise ValueError
                route = ("boards-api.greenhouse.io", f"/v1/boards/{board_token}/jobs", family)
            elif family == "lever":
                site = configuration["site"]
                region = configuration["region"]
                if type(site) is not str or not site or region not in {"global", "eu"}:
                    raise ValueError
                host = "api.eu.lever.co" if region == "eu" else "api.lever.co"
                route = (host, f"/v0/postings/{site}", family)
            else:
                raise ValueError
            if route in routes:
                raise ValueError
            routes.append(route)
    except (KeyError, TypeError, ValueError) as exc:
        raise RealATSTransportError("real_ats_route_binding_invalid") from exc
    if not routes:
        raise RealATSTransportError("real_ats_route_binding_invalid")
    return tuple(routes)


def _validate_timeout(request: httpx.Request, timeout_seconds: float) -> None:
    timeout = request.extensions.get("timeout")
    if not isinstance(timeout, Mapping) or set(timeout) != {"connect", "read", "write", "pool"}:
        raise RealATSTransportError("real_ats_timeout_invalid")
    if any(
        type(value) not in {int, float}
        or isinstance(value, bool)
        or not isfinite(value)
        or value <= 0
        or value > timeout_seconds
        for value in timeout.values()
    ):
        raise RealATSTransportError("real_ats_timeout_invalid")


def _validate_query(family: str, query: tuple[tuple[str, str], ...]) -> None:
    if family == "greenhouse":
        if query != (("content", "true"),):
            raise RealATSTransportError("real_ats_query_rejected")
        return
    if family != "lever" or len(query) != 3 or query[0] != ("mode", "json"):
        raise RealATSTransportError("real_ats_query_rejected")
    if query[1][0] != "limit" or query[2][0] != "skip":
        raise RealATSTransportError("real_ats_query_rejected")
    try:
        limit = int(query[1][1])
        skip = int(query[2][1])
    except (TypeError, ValueError) as exc:
        raise RealATSTransportError("real_ats_query_rejected") from exc
    if (
        skip < 0
        or skip > _MAX_LEVER_SKIP
        or skip % _MAX_LEVER_LIMIT != 0
        or (skip == _MAX_LEVER_SKIP and limit != 1)
        or (skip != _MAX_LEVER_SKIP and limit != _MAX_LEVER_LIMIT)
        or query[1][1] != str(limit)
        or query[2][1] != str(skip)
    ):
        raise RealATSTransportError("real_ats_query_rejected")


def _validate_request(
    request: httpx.Request,
    allowed_hosts: tuple[str, ...],
    *,
    routes: tuple[_Route, ...],
    timeout_seconds: float = 120.0,
) -> tuple[str, str]:
    """Apply the complete request boundary shared by real and fake seams."""
    try:
        if type(request) is not httpx.Request or request.method != "GET":
            raise RealATSTransportError("real_ats_request_rejected")
        try:
            content = request.content
        except Exception as exc:
            # Streaming/non-read request bodies must never escape as
            # httpx.RequestNotRead (or any other request implementation error).
            raise RealATSTransportError("real_ats_request_rejected") from exc
        if (
            content != b""
            or request.url.scheme != "https"
            or request.url.port not in (None, 443)
            or request.url.username not in (None, "")
            or request.url.password not in (None, "")
            or any(
                name.lower() in _CREDENTIAL_HEADERS
                or name.lower()
                in {"content-length", "content-type", "content-encoding", "transfer-encoding"}
                for name in request.headers
            )
        ):
            raise RealATSTransportError("real_ats_request_rejected")
        if request.url.host not in allowed_hosts:
            raise RealATSTransportError("real_ats_host_rejected")
        if request.headers.get("host") != request.url.host:
            raise RealATSTransportError("real_ats_origin_rejected")
        _validate_timeout(request, timeout_seconds)
        family: str | None = next(
            (
                candidate_family
                for host, path, candidate_family in routes
                if request.url.host == host and request.url.path == path
            ),
            None,
        )
        if family is None:
            raise RealATSTransportError("real_ats_path_rejected")
        _validate_query(family, tuple(request.url.params.multi_items()))
        return request.url.host, family
    except RealATSTransportError:
        raise
    except (TypeError, ValueError) as exc:
        raise RealATSTransportError("real_ats_request_rejected") from exc


class _BoundedResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, limit: int, deadline: float) -> None:
        self._stream = stream
        self._limit = limit
        self._deadline = deadline
        self._read = 0

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        try:
            async with asyncio.timeout(max(0.0, self._deadline - monotonic())):
                async for chunk in self._stream:
                    self._read += len(chunk)
                    if self._read > self._limit:
                        raise RealATSTransportError("real_ats_response_limit")
                    yield chunk
        except RealATSTransportError:
            raise
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            raise RealATSTransportError("real_ats_timeout") from exc
        except Exception as exc:
            raise RealATSTransportError("real_ats_network_failed") from exc

    async def aclose(self) -> None:
        try:
            await self._stream.aclose()
        except RealATSTransportError:
            raise
        except Exception as exc:
            raise RealATSTransportError("real_ats_network_failed") from exc


class RealATSTransport(httpx.AsyncBaseTransport):
    """Production transport.  It cannot be directly constructed by callers."""

    __slots__ = (
        "_allowed_hosts",
        "_calls",
        "_delegate",
        "_expires_at",
        "_max_requests",
        "_routes",
        "_timeout_seconds",
        "_window_cutoff",
        "_window_start",
        "_wire_limit_bytes",
    )
    _allowed_hosts: tuple[str, ...]
    _calls: int
    _delegate: httpx.AsyncBaseTransport
    _expires_at: datetime
    _max_requests: int
    _routes: tuple[_Route, ...]
    _timeout_seconds: float
    _window_cutoff: datetime
    _window_start: datetime
    _wire_limit_bytes: int

    def __init__(self, *args: object, _token: object = None, **kwargs: object) -> None:
        raise TypeError("real ATS transport is factory-only")

    @classmethod
    def _create(cls, capability: ApprovedRealATSCapability, *, _token: object) -> RealATSTransport:
        if _token is not _TOKEN or type(capability) is not ApprovedRealATSCapability:
            raise RealATSTransportError("real_ats_capability_required")
        claims = capability.claims
        if claims.allowed_hosts != REAL_ATS_HOSTS:
            raise RealATSTransportError()
        instance = object.__new__(cls)
        instance._allowed_hosts = claims.allowed_hosts
        instance._delegate = httpx.AsyncHTTPTransport(retries=0)
        instance._calls = 0
        instance._routes = _routes_from_source_configs(claims.source_configs)
        # Greenhouse is one request and Lever is five pages plus one bounded
        # overflow probe.  The plan budget remains the final tighter bound.
        planned_requests = sum(
            1 if family == "greenhouse" else 6 for _, _, family in instance._routes
        )
        instance._max_requests = min(claims.budget, planned_requests)
        if instance._max_requests <= 0:
            raise RealATSTransportError("real_ats_budget_invalid")
        instance._timeout_seconds = claims.timeout_seconds
        instance._window_start = claims.window_start
        instance._window_cutoff = claims.window_cutoff
        instance._expires_at = claims.expires_at
        instance._wire_limit_bytes = REAL_ATS_WIRE_LIMIT_BYTES
        return instance

    @property
    def calls(self) -> int:
        return self._calls

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._calls += 1
        _validate_request(
            request,
            self._allowed_hosts,
            routes=self._routes,
            timeout_seconds=self._timeout_seconds,
        )
        if self._calls > self._max_requests:
            raise RealATSTransportError("real_ats_request_budget_exhausted")
        now = datetime.now(UTC)
        if now < self._window_start or now > self._window_cutoff or now >= self._expires_at:
            raise RealATSTransportError("real_ats_window_inactive")
        timeout = cast(Mapping[str, object], request.extensions["timeout"])
        deadline = monotonic() + min(cast(float, value) for value in timeout.values())
        try:
            async with asyncio.timeout(max(0.0, deadline - monotonic())):
                response = await self._delegate.handle_async_request(request)
            content = getattr(response, "_content", None)
            if isinstance(content, bytes) and len(content) > self._wire_limit_bytes:
                raise RealATSTransportError("real_ats_response_limit")
            content_length = response.headers.get("content-length")
            try:
                content_length_value = int(content_length) if content_length is not None else None
            except ValueError as exc:
                raise RealATSTransportError("real_ats_response_invalid") from exc
            if content_length_value is not None and content_length_value > self._wire_limit_bytes:
                raise RealATSTransportError("real_ats_response_limit")
            if not isinstance(response.stream, httpx.AsyncByteStream):
                raise RealATSTransportError("real_ats_stream_invalid")
            response.stream = _BoundedResponseStream(
                response.stream, self._wire_limit_bytes, deadline
            )
            return response
        except RealATSTransportError:
            raise
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            raise RealATSTransportError("real_ats_timeout") from exc
        except (httpx.HTTPError, OSError) as exc:
            raise RealATSTransportError("real_ats_network_failed") from exc
        except Exception as exc:
            raise RealATSTransportError("real_ats_network_failed") from exc

    async def aclose(self) -> None:
        try:
            await self._delegate.aclose()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise RealATSTransportError("real_ats_network_failed") from exc


class RealATSTestTransport(httpx.AsyncBaseTransport):
    """Fixed-response, no-network transport used only by offline tests."""

    __slots__ = (
        "_allowed_hosts",
        "_current_time",
        "_expires_at",
        "_max_requests",
        "_responses",
        "_routes",
        "_timeout_seconds",
        "_window_cutoff",
        "_window_start",
        "_wire_limit_bytes",
        "calls",
        "requests",
    )

    def __init__(self, responses: Mapping[str, bytes], *, _token: object = None) -> None:
        if _token is not _TEST_TOKEN or type(responses) is not dict:
            raise TypeError("real ATS test transport is test-seam only")
        self._responses = dict(responses)
        self._allowed_hosts: tuple[str, ...] = ()
        self._current_time: datetime | None = None
        self._expires_at: datetime | None = None
        self._max_requests = 0
        self._routes: tuple[_Route, ...] = ()
        self._timeout_seconds = 0.0
        self._window_cutoff: datetime | None = None
        self._window_start: datetime | None = None
        self._wire_limit_bytes = REAL_ATS_WIRE_LIMIT_BYTES
        if any(
            type(value) is not bytes or len(value) > self._wire_limit_bytes
            for value in responses.values()
        ):
            raise RealATSTransportError("real_ats_response_limit")
        self.calls = 0
        self.requests: list[tuple[str, str]] = []

    def _seal_hosts(
        self,
        hosts: tuple[str, ...],
        source_configs: tuple[Mapping[str, object], ...],
        *,
        budget: int,
        timeout_seconds: float,
        window_start: datetime,
        window_cutoff: datetime,
        expires_at: datetime,
        current_time: datetime,
    ) -> None:
        if self._allowed_hosts or hosts != REAL_ATS_HOSTS:
            raise RealATSTransportError("real_ats_host_binding_invalid")
        routes = _routes_from_source_configs(source_configs)
        if any(host not in hosts for host, _path, _family in routes):
            raise RealATSTransportError("real_ats_host_binding_invalid")
        if (
            type(budget) is not int
            or budget <= 0
            or type(timeout_seconds) is not float
            or not isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or any(
                type(value) is not datetime or value.tzinfo is not UTC
                for value in (window_start, window_cutoff, expires_at, current_time)
            )
            or not window_start < expires_at <= window_cutoff
            or current_time < window_start
            or current_time > window_cutoff
            or current_time >= expires_at
        ):
            raise RealATSTransportError("real_ats_binding_invalid")
        self._allowed_hosts = hosts
        self._routes = routes
        planned = sum(1 if family == "greenhouse" else 6 for _, _path, family in routes)
        self._max_requests = min(budget, planned)
        self._timeout_seconds = timeout_seconds
        self._window_start = window_start
        self._window_cutoff = window_cutoff
        self._expires_at = expires_at
        self._current_time = current_time

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.requests.append((request.url.host, request.url.path))
        _validate_request(
            request,
            self._allowed_hosts,
            routes=self._routes,
            timeout_seconds=self._timeout_seconds,
        )
        if self.calls > self._max_requests:
            raise RealATSTransportError("real_ats_request_budget_exhausted")
        if (
            self._current_time is None
            or self._window_start is None
            or self._window_cutoff is None
            or self._expires_at is None
            or self._current_time < self._window_start
            or self._current_time > self._window_cutoff
            or self._current_time >= self._expires_at
        ):
            raise RealATSTransportError("real_ats_window_inactive")
        content = self._responses.get(request.url.path)
        if content is None:
            return httpx.Response(404, request=request, content=b"{}")
        if type(content) is not bytes or len(content) > self._wire_limit_bytes:
            raise RealATSTransportError("real_ats_response_limit")
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "application/json"},
            content=content,
        )


def make_real_ats_transport(capability: ApprovedRealATSCapability) -> RealATSTransport:
    """The sole production construction path; it is unavailable without claims."""
    try:
        if type(capability) is not ApprovedRealATSCapability:
            raise RealATSTransportError("real_ats_capability_required")
        return RealATSTransport._create(capability, _token=_TOKEN)
    except (RealATSCapabilityError, RealATSTransportError):
        raise
    except Exception as exc:
        raise RealATSTransportError() from exc


def make_test_real_ats_transport(responses: Mapping[str, bytes]) -> RealATSTestTransport:
    return RealATSTestTransport(responses, _token=_TEST_TOKEN)


__all__ = [
    "REAL_ATS_HOSTS",
    "REAL_ATS_WIRE_LIMIT_BYTES",
    "RealATSTestTransport",
    "RealATSTransport",
    "RealATSTransportError",
    "make_real_ats_transport",
    "make_test_real_ats_transport",
]
