"""Bounded Greenhouse Boards adapter (one listing request, never N+1)."""

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal, overload
from urllib.parse import urlsplit

import httpx

from role_radar.collectors.bounded_http import BoundedHttpClient, BoundedHttpError
from role_radar.collectors.bounded_json import (
    BoundedJsonError,
    canonical_json_bytes,
    ensure_object,
    loads_bounded,
)
from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionMetrics,
    CollectionStopCode,
    CollectionSuccess,
    CollectorFailureCode,
    RejectionCounts,
)
from role_radar.collectors.policy import GREENHOUSE_POLICY, CollectionRunBudget
from role_radar.collectors.protocols import CollectionContext, CollectorRuntime, SourceSnapshot
from role_radar.collectors.raw_job_bounds import (
    CanonicalBatch,
    RawJobBoundsError,
    validate_raw_job,
)
from role_radar.domain.dto import RawJob
from role_radar.sources.configuration import GreenhouseSourceConfig

GREENHOUSE_BOARDS_API_BASE = "https://boards-api.greenhouse.io/v1/boards"
_GREENHOUSE_HOSTS = frozenset({"boards.greenhouse.io"})
Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class GreenhouseCollector:
    """Only provider mapping; transport bounds and retries live elsewhere."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
        budget: CollectionRunBudget | None = None,
        user_agent: str = "role-radar/0.1 (+homelab)",
        config: GreenhouseSourceConfig | None = None,
        # Compatibility-only for F2/F5 fixtures. Production registry never supplies it.
        client: httpx.AsyncClient | None = None,
        timeout: float | None = None,
    ) -> None:
        del timeout
        self._transport = transport
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or asyncio.sleep
        self._budget = budget
        self._user_agent = user_agent
        self._config = config
        self._legacy_client = client

    @overload
    async def collect(
        self, context: CollectionContext, runtime: None = None
    ) -> list[RawJob]: ...

    @overload
    async def collect(
        self, context: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionSuccess | CollectionFailure: ...

    async def collect(
        self,
        context: SourceSnapshot | CollectionContext,
        runtime: CollectorRuntime | None = None,
    ) -> CollectionSuccess | CollectionFailure | list[RawJob]:
        if isinstance(context, CollectionContext):
            return await self._collect_legacy(context)
        if self._legacy_client is not None:
            config = self._config or GreenhouseSourceConfig.model_validate(
                dict(context.configuration)
            )
            return await self._collect_legacy(
                CollectionContext(
                    source_id=context.source_id,
                    board_token=config.board_token,
                    company=config.company,
                    source_name=context.name,
                )
            )
        try:
            config = self._config or GreenhouseSourceConfig.model_validate(
                dict(context.configuration)
            )
        except ValueError:
            return CollectionFailure(
                status="failed",
                error_code=CollectorFailureCode.CONFIG,
                metrics=CollectionMetrics(),
            )
        runtime = runtime or CollectorRuntime()
        budget = runtime.budget or self._budget or CollectionRunBudget()
        start = runtime.clock()
        path = f"/v1/boards/{config.board_token}/jobs"
        metrics = CollectionMetrics(logical_requests=1, logical_pages=1)
        try:
            async with BoundedHttpClient(
                GREENHOUSE_POLICY.http,
                transport=runtime.transport or self._transport,
                clock=runtime.clock if runtime else self._clock,
                sleeper=runtime.sleeper if runtime else self._sleeper,
                budget=budget,
                user_agent=self._user_agent,
            ) as http:
                response = await http.get(path, query=(("content", "true"),))
            metrics = self._with_transfer(metrics, response.metrics, runtime.clock() - start)
            try:
                if runtime.clock() - start >= GREENHOUSE_POLICY.http.source_deadline_seconds:
                    return self._failure(
                        CollectorFailureCode.DEADLINE,
                        metrics,
                        stop_code=CollectionStopCode.DEADLINE_EXPIRED,
                    )
                payload = loads_bounded(
                    response.body,
                    max_depth=GREENHOUSE_POLICY.json_max_depth,
                    max_nodes=GREENHOUSE_POLICY.json_max_nodes,
                )
                top = ensure_object(payload)
                jobs_value = top.get("jobs")
                if not isinstance(jobs_value, list):
                    return self._failure(
                        CollectorFailureCode.PAYLOAD_INVALID,
                        metrics,
                        stop_code=CollectionStopCode.INVALID_PAYLOAD,
                    )
            except BoundedJsonError:
                return self._failure(CollectorFailureCode.INVALID_JSON, metrics)

            if len(jobs_value) > GREENHOUSE_POLICY.max_items:
                return self._failure(
                    CollectorFailureCode.JOB_LIMIT,
                    metrics,
                    stop_code=CollectionStopCode.JOB_LIMIT_REACHED,
                )
            if runtime.clock() - start >= GREENHOUSE_POLICY.http.source_deadline_seconds:
                return self._failure(
                    CollectorFailureCode.DEADLINE,
                    metrics,
                    stop_code=CollectionStopCode.DEADLINE_EXPIRED,
                )
            return self._map_jobs(context, jobs_value, metrics, start, runtime.clock)
        except BoundedHttpError as exc:
            transfer = exc.metrics
            metrics = self._with_transfer(metrics, transfer, runtime.clock() - start)
            return self._failure(
                exc.code,
                metrics,
                retryable=exc.retryable,
                http_status=exc.http_status,
                stop_code=self._stop_code(exc.stop_code),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return self._failure(CollectorFailureCode.INTERNAL, metrics)

    async def _collect_legacy(self, context: CollectionContext) -> list[RawJob]:
        """Keep old local fixtures working without making them the production seam."""
        if self._legacy_client is None:
            raise TypeError("legacy CollectionContext requires a compatibility client")
        config = GreenhouseSourceConfig(board_token=context.board_token, company=context.company)
        response = await self._legacy_client.get(
            f"{GREENHOUSE_BOARDS_API_BASE}/{config.board_token}/jobs",
            params={"content": "true"},
            headers={"User-Agent": self._user_agent, "Accept": "application/json"},
        )
        response.raise_for_status()
        payload = response.json()
        jobs = payload.get("jobs", []) if isinstance(payload, dict) else []
        result: list[RawJob] = []
        for item in jobs if isinstance(jobs, list) else []:
            if not isinstance(item, dict) or "id" not in item:
                continue
            result.append(
                self._raw_values(item, context.source_name, config.company or context.source_name)
            )
        return result

    def _map_jobs(
        self,
        snapshot: SourceSnapshot,
        jobs: list[Any],
        metrics: CollectionMetrics,
        start: float,
        clock: Any,
    ) -> CollectionSuccess | CollectionFailure:
        config = self._config or GreenhouseSourceConfig.model_validate(dict(snapshot.configuration))
        company = config.company or snapshot.name
        accepted: list[RawJob] = []
        rejection = RejectionCounts()
        seen: dict[str, bytes] = {}
        batch = CanonicalBatch(GREENHOUSE_POLICY.batch_limit_bytes)
        for item in jobs:
            if clock() - start >= GREENHOUSE_POLICY.http.source_deadline_seconds:
                return self._failure(
                    CollectorFailureCode.DEADLINE,
                    metrics,
                    stop_code=CollectionStopCode.DEADLINE_EXPIRED,
                )
            try:
                if (
                    not isinstance(item, dict)
                    or "id" not in item
                    or item["id"] is None
                    or (isinstance(item["id"], str) and not item["id"].strip())
                ):
                    raise RawJobBoundsError("invalid")
                raw = self._raw_values(item, snapshot.name, company)
                canonical = validate_raw_job(
                    raw,
                    description_limit_bytes=GREENHOUSE_POLICY.description_limit_bytes,
                    structured_data_limit_bytes=GREENHOUSE_POLICY.structured_data_limit_bytes,
                    max_depth=GREENHOUSE_POLICY.json_max_depth,
                )
                duplicate_key = canonical_json_bytes(
                    raw.model_dump(mode="json", exclude={"collected_at"})
                )
                external_id = raw.external_id
                if external_id in seen:
                    if seen[external_id] == duplicate_key:
                        rejection = RejectionCounts(
                            rejection.invalid_item,
                            rejection.oversized_item,
                            rejection.duplicate_identical + 1,
                            rejection.duplicate_conflict,
                        )
                    else:
                        rejection = RejectionCounts(
                            rejection.invalid_item,
                            rejection.oversized_item,
                            rejection.duplicate_identical,
                            rejection.duplicate_conflict + 1,
                        )
                    continue
                batch.add(canonical)
                seen[external_id] = duplicate_key
                accepted.append(raw)
            except (RawJobBoundsError, ValueError) as exc:
                kind = exc.kind if isinstance(exc, RawJobBoundsError) else "invalid"
                rejection = RejectionCounts(
                    rejection.invalid_item + (kind == "invalid"),
                    rejection.oversized_item + (kind == "oversized"),
                    rejection.duplicate_identical,
                    rejection.duplicate_conflict,
                )
                if kind == "batch":
                    failed_metrics = CollectionMetrics(
                        logical_requests=metrics.logical_requests,
                        logical_pages=metrics.logical_pages,
                        wire_attempts=metrics.wire_attempts,
                        retries=metrics.retries,
                        wire_bytes=metrics.wire_bytes,
                        decoded_bytes=metrics.decoded_bytes,
                        duration_seconds=max(0.0, clock() - start),
                    )
                    return self._failure(
                        CollectorFailureCode.BATCH_LIMIT,
                        failed_metrics,
                        stop_code=CollectionStopCode.BATCH_LIMIT_REACHED,
                    )
        data_metrics = self._data_metrics(
            metrics, len(jobs), accepted, rejection, batch.size, clock() - start
        )
        if jobs and not accepted:
            return self._failure(
                CollectorFailureCode.NO_VALID_ITEMS,
                data_metrics,
                rejection_counts=rejection,
                stop_code=CollectionStopCode.NO_VALID_ITEMS,
            )
        status: Literal["ok", "partial"] = (
            "partial"
            if any((rejection.invalid_item, rejection.oversized_item, rejection.duplicate_items))
            else "ok"
        )
        return CollectionSuccess(
            status=status, jobs=tuple(accepted), metrics=data_metrics, rejection_counts=rejection
        )

    @staticmethod
    def _raw_values(item: dict[str, Any], source_name: str, company: str) -> RawJob:
        location = item.get("location")
        if isinstance(location, dict):
            location = location.get("name")
        elif location is not None and not isinstance(location, str):
            location = str(location)
        absolute_url = item.get("absolute_url")
        if absolute_url is not None:
            parsed = urlsplit(str(absolute_url))
            if parsed.hostname not in _GREENHOUSE_HOSTS:
                raise RawJobBoundsError("invalid")
        application_url = item.get("application_url", absolute_url)
        if application_url is not None:
            parsed_application = urlsplit(str(application_url))
            if parsed_application.hostname not in _GREENHOUSE_HOSTS:
                raise RawJobBoundsError("invalid")
        content = item.get("content")
        if content is not None and not isinstance(content, str):
            raise RawJobBoundsError("invalid")
        structured: dict[str, Any] = {
            key: item[key]
            for key in ("id", "title", "location", "absolute_url", "updated_at", "metadata")
            if key in item
        }
        return RawJob(
            source="greenhouse",
            external_id=str(item["id"]),
            source_url=absolute_url,
            application_url=application_url,
            title=(
                item.get("title", "")
                if isinstance(item.get("title", ""), str)
                else str(item.get("title", ""))
            ),
            company=company or source_name,
            location=location,
            description=content,
            structured_data=structured,
            collected_at=datetime.now(UTC),
        )

    async def __aenter__(self) -> "GreenhouseCollector":
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        return None

    async def aclose(self) -> None:
        return None

    @staticmethod
    def _with_transfer(
        base: CollectionMetrics, transfer: Any, duration: float
    ) -> CollectionMetrics:
        return CollectionMetrics(
            logical_requests=base.logical_requests,
            logical_pages=base.logical_pages,
            wire_attempts=transfer.wire_attempts,
            retries=transfer.retries,
            wire_bytes=transfer.wire_bytes,
            decoded_bytes=transfer.decoded_bytes,
            duration_seconds=max(0.0, duration),
        )

    @staticmethod
    def _data_metrics(
        base: CollectionMetrics,
        provider: int,
        jobs: list[RawJob],
        rejection: RejectionCounts,
        batch: int,
        duration: float,
    ) -> CollectionMetrics:
        return CollectionMetrics(
            logical_requests=base.logical_requests,
            logical_pages=base.logical_pages,
            wire_attempts=base.wire_attempts,
            retries=base.retries,
            wire_bytes=base.wire_bytes,
            decoded_bytes=base.decoded_bytes,
            provider_items=provider,
            accepted_items=len(jobs),
            rejected_items=rejection.rejected_items,
            duplicate_items=rejection.duplicate_items,
            canonical_batch_bytes=batch,
            duration_seconds=max(0.0, duration),
        )

    @staticmethod
    def _failure(
        code: CollectorFailureCode,
        metrics: CollectionMetrics,
        *,
        rejection_counts: RejectionCounts | None = None,
        retryable: bool = False,
        http_status: int | None = None,
        stop_code: CollectionStopCode | None = None,
    ) -> CollectionFailure:
        return CollectionFailure(
            status="failed",
            error_code=code,
            metrics=metrics,
            rejection_counts=rejection_counts or RejectionCounts(),
            retryable=retryable,
            http_status=http_status,
            stop_code=stop_code,
        )

    @staticmethod
    def _stop_code(value: str | None) -> CollectionStopCode | None:
        try:
            return CollectionStopCode(value) if value else None
        except ValueError:
            return None
