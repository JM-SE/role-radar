"""Fixed-origin, GET-only HTTP transport with bounded streaming."""

import asyncio
import email.utils
import time
import zlib
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from role_radar.collectors.outcomes import CollectorFailureCode
from role_radar.collectors.policy import (
    RETRYABLE_STATUSES,
    CollectionRunBudget,
    HttpPolicy,
)

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class TransferMetrics:
    wire_attempts: int = 0
    retries: int = 0
    wire_bytes: int = 0
    decoded_bytes: int = 0


class BoundedHttpError(Exception):
    def __init__(
        self,
        code: CollectorFailureCode,
        *,
        metrics: TransferMetrics,
        retryable: bool = False,
        http_status: int | None = None,
        stop_code: str | None = None,
    ) -> None:
        self.code = code
        self.metrics = metrics
        self.retryable = retryable
        self.http_status = http_status
        self.stop_code = stop_code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class BoundedHttpResponse:
    body: bytes
    status_code: int
    metrics: TransferMetrics


def validate_relative_path(path: str, policy: HttpPolicy) -> None:
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in path
        or any(part in {".", ".."} for part in parsed.path.split("/"))
        or not parsed.path.startswith(policy.allowed_path_prefix)
    ):
        raise BoundedHttpError(CollectorFailureCode.ORIGIN, metrics=TransferMetrics())


class BoundedHttpClient:
    def __init__(
        self,
        policy: HttpPolicy,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Clock = time.monotonic,
        sleeper: Sleeper = asyncio.sleep,
        budget: CollectionRunBudget | None = None,
        user_agent: str = "role-radar/0.1 (+homelab)",
    ) -> None:
        self.policy = policy
        self._transport = transport
        self._clock = clock
        self._sleeper = sleeper
        self._budget = budget or CollectionRunBudget()
        self._user_agent = "".join(char for char in user_agent if ord(char) >= 32)[:255]
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "BoundedHttpClient":
        self._client = httpx.AsyncClient(
            base_url=self.policy.origin,
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
            limits=httpx.Limits(
                max_connections=1, max_keepalive_connections=1, keepalive_expiry=30.0
            ),
            transport=self._transport,
        )
        return self

    async def __aexit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(
        self,
        path: str,
        *,
        query: Sequence[tuple[str, str]] = (),
        deadline_seconds: float | None = None,
    ) -> BoundedHttpResponse:
        validate_relative_path(path, self.policy)
        if any(
            key not in self.policy.allowed_query_keys
            or (
                self.policy.allowed_query_values is not None
                and key in self.policy.allowed_query_values
                and value not in self.policy.allowed_query_values[key]
            )
            for key, value in query
        ):
            raise BoundedHttpError(CollectorFailureCode.ORIGIN, metrics=TransferMetrics())
        if self._client is None:
            raise RuntimeError("bounded HTTP client is not open")

        deadline = self._clock() + (
            self.policy.source_deadline_seconds if deadline_seconds is None else deadline_seconds
        )
        total = TransferMetrics()
        for attempt in range(self.policy.max_retries + 1):
            if self._clock() >= deadline:
                raise BoundedHttpError(
                    CollectorFailureCode.DEADLINE,
                    metrics=total,
                    stop_code="deadline_expired",
                )
            if not self._budget.acquire():
                raise BoundedHttpError(
                    CollectorFailureCode.REQUEST_BUDGET,
                    metrics=total,
                    stop_code="request_budget_exhausted",
                )
            total = TransferMetrics(
                wire_attempts=total.wire_attempts + 1,
                retries=attempt,
                wire_bytes=total.wire_bytes,
                decoded_bytes=total.decoded_bytes,
            )
            headers = {
                "Accept": "application/json",
                "Accept-Encoding": "identity, gzip",
                "User-Agent": self._user_agent,
            }
            try:
                result = await self._attempt(path, query, headers, deadline, total)
            except BoundedHttpError as exc:
                total = exc.metrics
                if not exc.retryable:
                    raise exc
                if attempt >= self.policy.max_retries:
                    raise BoundedHttpError(
                        exc.code,
                        metrics=exc.metrics,
                        retryable=True,
                        http_status=exc.http_status,
                        stop_code=exc.stop_code or "retries_exhausted",
                    ) from exc
                await self._backoff(None, attempt, deadline, total)
                continue
            if result.status_code in RETRYABLE_STATUSES:
                if result.status_code == 429:
                    retry_after = result.headers.get("retry-after")
                    delay = self._retry_after(retry_after)
                    if delay is not None and (delay > 30.0 or self._clock() + delay >= deadline):
                        raise BoundedHttpError(
                            CollectorFailureCode.RATE_LIMITED,
                            metrics=result.metrics,
                            retryable=True,
                            http_status=429,
                            stop_code=(
                                "deadline_expired"
                                if self._clock() + delay >= deadline
                                else "rate_limited"
                            ),
                        )
                else:
                    delay = None
                if attempt >= self.policy.max_retries:
                    code = (
                        CollectorFailureCode.RATE_LIMITED
                        if result.status_code == 429
                        else CollectorFailureCode.UPSTREAM
                    )
                    raise BoundedHttpError(
                        code,
                        metrics=result.metrics,
                        retryable=True,
                        http_status=result.status_code,
                        stop_code="retries_exhausted",
                    )
                await self._backoff(delay, attempt, deadline, result.metrics)
                total = result.metrics
                continue
            if 300 <= result.status_code <= 399:
                raise BoundedHttpError(
                    CollectorFailureCode.REDIRECT,
                    metrics=result.metrics,
                    http_status=result.status_code,
                )
            if 400 <= result.status_code <= 499:
                raise BoundedHttpError(
                    CollectorFailureCode.CLIENT_STATUS,
                    metrics=result.metrics,
                    http_status=result.status_code,
                )
            if result.status_code >= 500:
                raise BoundedHttpError(
                    CollectorFailureCode.UPSTREAM,
                    metrics=result.metrics,
                    http_status=result.status_code,
                )
            return BoundedHttpResponse(result.body, result.status_code, result.metrics)
        raise AssertionError("retry loop exhausted unexpectedly")

    async def _attempt(
        self,
        path: str,
        query: Sequence[tuple[str, str]],
        headers: dict[str, str],
        deadline: float,
        metrics: TransferMetrics,
    ) -> "_AttemptResult":
        wire = metrics.wire_bytes
        decoded = metrics.decoded_bytes
        chunks: list[bytes] = []
        try:
            client = self._client
            if client is None:
                raise RuntimeError("bounded HTTP client is not open")
            async with client.stream(
                "GET", path, params=list(query), headers=headers
            ) as response:
                if response.status_code >= 200 and response.status_code < 300:
                    self._validate_content_headers(response.headers, metrics)
                decoder = (
                    self._decoder(response.headers.get("content-encoding"), metrics)
                    if 200 <= response.status_code < 300
                    else None
                )
                raw_chunks = (
                    _single_chunk(response.content)
                    if response.is_stream_consumed
                    else response.aiter_raw()
                )
                async for raw in raw_chunks:
                    if self._clock() >= deadline:
                        raise BoundedHttpError(
                            CollectorFailureCode.DEADLINE,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                            stop_code="deadline_expired",
                        )
                    wire += len(raw)
                    if wire > self.policy.wire_limit_bytes:
                        raise BoundedHttpError(
                            CollectorFailureCode.RESPONSE_TOO_LARGE,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                            stop_code="response_limit",
                        )
                    try:
                        out = decoder(raw) if decoder is not None else raw
                    except (OSError, zlib.error) as exc:
                        raise BoundedHttpError(
                            CollectorFailureCode.DECOMPRESSION,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                        ) from exc
                    decoded += len(out)
                    if decoded > self.policy.decoded_limit_bytes:
                        raise BoundedHttpError(
                            CollectorFailureCode.RESPONSE_TOO_LARGE,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                            stop_code="response_limit",
                        )
                    if (
                        decoder is not None
                        and wire > self.policy.gzip_ratio_floor_bytes
                        and decoded > wire * self.policy.gzip_expansion_ratio
                    ):
                        raise BoundedHttpError(
                            CollectorFailureCode.DECOMPRESSION,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                            stop_code="decompression_limit",
                        )
                    chunks.append(out)
                if decoder is not None:
                    try:
                        out = decoder.finish()
                    except (OSError, zlib.error) as exc:
                        raise BoundedHttpError(
                            CollectorFailureCode.DECOMPRESSION,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                        ) from exc
                    decoded += len(out)
                    if (
                        wire > self.policy.gzip_ratio_floor_bytes
                        and decoded > wire * self.policy.gzip_expansion_ratio
                    ):
                        raise BoundedHttpError(
                            CollectorFailureCode.DECOMPRESSION,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                            stop_code="decompression_limit",
                        )
                    if decoded > self.policy.decoded_limit_bytes:
                        raise BoundedHttpError(
                            CollectorFailureCode.RESPONSE_TOO_LARGE,
                            metrics=self._transfer_metrics(metrics, wire, decoded),
                            stop_code="response_limit",
                        )
                    chunks.append(out)
                if self._clock() >= deadline:
                    raise BoundedHttpError(
                        CollectorFailureCode.DEADLINE,
                        metrics=self._transfer_metrics(metrics, wire, decoded),
                        stop_code="deadline_expired",
                    )
                result_metrics = self._transfer_metrics(metrics, wire, decoded)
                return _AttemptResult(
                    response.status_code, response.headers, b"".join(chunks), result_metrics
                )
        except asyncio.CancelledError:
            raise
        except BoundedHttpError:
            raise
        except httpx.ConnectTimeout as exc:
            raise BoundedHttpError(
                CollectorFailureCode.CONNECT,
                metrics=self._transfer_metrics(metrics, wire, decoded),
                retryable=True,
            ) from exc
        except httpx.PoolTimeout as exc:
            raise BoundedHttpError(
                CollectorFailureCode.POOL,
                metrics=self._transfer_metrics(metrics, wire, decoded),
                retryable=True,
            ) from exc
        except httpx.ReadTimeout as exc:
            raise BoundedHttpError(
                CollectorFailureCode.READ,
                metrics=self._transfer_metrics(metrics, wire, decoded),
                retryable=True,
            ) from exc
        except httpx.ConnectError as exc:
            raise BoundedHttpError(
                CollectorFailureCode.CONNECT,
                metrics=self._transfer_metrics(metrics, wire, decoded),
                retryable=True,
            ) from exc
        except httpx.WriteTimeout as exc:
            raise BoundedHttpError(
                CollectorFailureCode.NETWORK,
                metrics=self._transfer_metrics(metrics, wire, decoded),
            ) from exc
        except httpx.NetworkError as exc:
            raise BoundedHttpError(
                CollectorFailureCode.NETWORK,
                metrics=self._transfer_metrics(metrics, wire, decoded),
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise BoundedHttpError(
                CollectorFailureCode.NETWORK,
                metrics=self._transfer_metrics(metrics, wire, decoded),
                retryable=True,
            ) from exc

    @staticmethod
    def _transfer_metrics(
        base: TransferMetrics, wire: int, decoded: int
    ) -> TransferMetrics:
        return TransferMetrics(base.wire_attempts, base.retries, wire, decoded)

    def _validate_content_headers(
        self, headers: httpx.Headers, metrics: TransferMetrics
    ) -> None:
        content_type = headers.get("content-type", "")
        parts = [part.strip() for part in content_type.split(";")]
        media = parts[0].lower()
        if not (
            media == "application/json"
            or (media.startswith("application/") and media.endswith("+json"))
        ):
            raise BoundedHttpError(CollectorFailureCode.CONTENT_TYPE, metrics=metrics)
        for part in parts[1:]:
            if part.lower().startswith("charset=") and part.split("=", 1)[
                1
            ].strip().lower() not in {"utf-8", '"utf-8"'}:
                raise BoundedHttpError(CollectorFailureCode.CONTENT_TYPE, metrics=metrics)

    @staticmethod
    def _decoder(
        value: str | None, metrics: TransferMetrics
    ) -> "_GzipDecoder | None":
        if value is None or value.strip().lower() in {"", "identity"}:
            return None
        if value.strip().lower() != "gzip":
            raise BoundedHttpError(CollectorFailureCode.CONTENT_ENCODING, metrics=metrics)
        return _GzipDecoder()

    async def _backoff(
        self,
        delay: float | None,
        attempt: int,
        deadline: float,
        metrics: TransferMetrics,
    ) -> None:
        actual = delay if delay is not None else float(1 << attempt)
        if self._clock() + actual >= deadline:
            raise BoundedHttpError(
                CollectorFailureCode.DEADLINE,
                metrics=metrics,
                stop_code="deadline_expired",
            )
        await self._sleeper(actual)

    @staticmethod
    def _retry_after(value: str | None) -> float | None:
        if value is None:
            return None
        if value.isdigit():
            return float(int(value))
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed is None:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return max(0.0, (parsed - datetime.now(UTC)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return None


@dataclass(frozen=True, slots=True)
class _AttemptResult:
    status_code: int
    headers: httpx.Headers
    body: bytes
    metrics: TransferMetrics


class _GzipDecoder:
    def __init__(self) -> None:
        self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def __call__(self, value: bytes) -> bytes:
        return self._decoder.decompress(value)

    def finish(self) -> bytes:
        if not self._decoder.eof or self._decoder.unused_data:
            raise zlib.error("incomplete gzip stream")
        return self._decoder.flush()


async def _single_chunk(value: bytes) -> AsyncIterator[bytes]:
    yield value
