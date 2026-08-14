"""Fixed-origin, single-request Jobicy LATAM JSON collector."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

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
from role_radar.collectors.policy import JOBICY_POLICY, CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.raw_job_bounds import (
    CanonicalBatch,
    RawJobBoundsError,
    validate_raw_job,
)
from role_radar.domain.dto import RawJob
from role_radar.sources.configuration import JobicySourceConfigV1

JOBICY_API_ORIGIN = "https://jobicy.com"
JOBICY_API_PATH = "/api/v2/remote-jobs"
JOBICY_QUERY: tuple[tuple[str, str], ...] = (("count", "100"), ("geo", "latam"))

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]


class JobicyCollector:
    """The adapter owns mapping only; cadence is owned by the free-source pipeline."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Clock | None = None,
        sleeper: Sleeper | None = None,
        budget: CollectionRunBudget | None = None,
        user_agent: str = "role-radar/0.1 (+homelab)",
        config: JobicySourceConfigV1 | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or asyncio.sleep
        self._budget = budget
        self._user_agent = user_agent
        self._config = config

    async def collect(
        self, snapshot: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionSuccess | CollectionFailure:
        try:
            config = self._config or JobicySourceConfigV1.model_validate(
                dict(snapshot.configuration)
            )
            if config.region != "latam" or config.remote_only is not True:
                return self._failure(CollectorFailureCode.CONFIG)
        except ValueError:
            return self._failure(CollectorFailureCode.CONFIG)

        runtime = runtime or CollectorRuntime()
        budget = runtime.budget or self._budget or CollectionRunBudget(1)
        started = runtime.clock()
        metrics = CollectionMetrics(logical_requests=1, logical_pages=1)
        try:
            async with BoundedHttpClient(
                JOBICY_POLICY.http,
                transport=runtime.transport or self._transport,
                clock=runtime.clock,
                sleeper=runtime.sleeper,
                budget=budget,
                user_agent=self._user_agent,
            ) as http:
                response = await http.get(
                    JOBICY_API_PATH,
                    query=JOBICY_QUERY,
                    deadline_seconds=JOBICY_POLICY.http.source_deadline_seconds,
                )
            metrics = _with_transfer(metrics, response.metrics, runtime.clock() - started)
            if runtime.clock() - started >= JOBICY_POLICY.http.source_deadline_seconds:
                return self._failure(
                    CollectorFailureCode.DEADLINE,
                    metrics,
                    stop_code=CollectionStopCode.DEADLINE_EXPIRED,
                )
            try:
                payload = ensure_object(
                    loads_bounded(
                        response.body,
                        max_depth=JOBICY_POLICY.json_max_depth,
                        max_nodes=JOBICY_POLICY.json_max_nodes,
                    )
                )
            except BoundedJsonError:
                return self._failure(CollectorFailureCode.INVALID_JSON, metrics)
            items = payload.get("jobs")
            if not isinstance(items, list):
                return self._failure(
                    CollectorFailureCode.PAYLOAD_INVALID,
                    metrics,
                    stop_code=CollectionStopCode.INVALID_PAYLOAD,
                )
            if len(items) > JOBICY_POLICY.max_items:
                return self._failure(
                    CollectorFailureCode.JOB_LIMIT,
                    metrics,
                    stop_code=CollectionStopCode.JOB_LIMIT_REACHED,
                )
            return self._map_items(snapshot, items, metrics, started, runtime.clock)
        except BoundedHttpError as exc:
            metrics = _with_transfer(metrics, exc.metrics, runtime.clock() - started)
            return self._failure(
                exc.code,
                metrics,
                retryable=exc.retryable,
                http_status=exc.http_status,
                stop_code=_stop_code(exc.stop_code),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return self._failure(CollectorFailureCode.INTERNAL, metrics)

    def _map_items(
        self,
        snapshot: SourceSnapshot,
        items: list[Any],
        metrics: CollectionMetrics,
        started: float,
        clock: Clock,
    ) -> CollectionSuccess | CollectionFailure:
        accepted: list[RawJob] = []
        rejection = RejectionCounts()
        seen: dict[str, bytes] = {}
        batch = CanonicalBatch(JOBICY_POLICY.batch_limit_bytes)
        for item in items:
            if clock() - started >= JOBICY_POLICY.http.source_deadline_seconds:
                return self._failure(
                    CollectorFailureCode.DEADLINE,
                    _with_transfer(metrics, None, clock() - started),
                    rejection_counts=rejection,
                    stop_code=CollectionStopCode.DEADLINE_EXPIRED,
                )
            try:
                values = _job_values(item, snapshot.name)
                raw = RawJob.model_validate(values)
                canonical = validate_raw_job(
                    raw,
                    description_limit_bytes=JOBICY_POLICY.description_limit_bytes,
                    structured_data_limit_bytes=JOBICY_POLICY.structured_data_limit_bytes,
                    max_depth=JOBICY_POLICY.json_max_depth,
                )
                if raw.external_id is None:
                    raise ValueError("missing external id")
                duplicate_key = canonical_json_bytes(
                    raw.model_dump(mode="json", exclude={"collected_at"})
                )
                if raw.external_id in seen:
                    identical = duplicate_key == seen[raw.external_id]
                    rejection = RejectionCounts(
                        rejection.invalid_item,
                        rejection.oversized_item,
                        rejection.duplicate_identical + identical,
                        rejection.duplicate_conflict + (not identical),
                    )
                    continue
                batch.add(canonical)
                seen[raw.external_id] = duplicate_key
                accepted.append(raw)
            except RawJobBoundsError as exc:
                rejection = RejectionCounts(
                    rejection.invalid_item + (exc.kind == "invalid"),
                    rejection.oversized_item + (exc.kind == "oversized"),
                    rejection.duplicate_identical,
                    rejection.duplicate_conflict,
                )
                if exc.kind == "batch":
                    return self._failure(
                        CollectorFailureCode.BATCH_LIMIT,
                        _with_transfer(metrics, None, clock() - started),
                        rejection_counts=rejection,
                        stop_code=CollectionStopCode.BATCH_LIMIT_REACHED,
                    )
            except (TypeError, ValueError):
                rejection = RejectionCounts(
                    rejection.invalid_item + 1,
                    rejection.oversized_item,
                    rejection.duplicate_identical,
                    rejection.duplicate_conflict,
                )

        final_metrics = _with_transfer(
            CollectionMetrics(
                logical_requests=metrics.logical_requests,
                logical_pages=metrics.logical_pages,
                wire_attempts=metrics.wire_attempts,
                retries=metrics.retries,
                wire_bytes=metrics.wire_bytes,
                decoded_bytes=metrics.decoded_bytes,
                provider_items=len(items),
                accepted_items=len(accepted),
                rejected_items=rejection.rejected_items,
                duplicate_items=rejection.duplicate_items,
                canonical_batch_bytes=batch.size,
            ),
            None,
            clock() - started,
        )
        if not accepted and items:
            return self._failure(
                CollectorFailureCode.NO_VALID_ITEMS,
                final_metrics,
                rejection_counts=rejection,
                stop_code=CollectionStopCode.NO_VALID_ITEMS,
            )
        return CollectionSuccess(
            status="partial" if rejection.rejected_items or rejection.duplicate_items else "ok",
            jobs=tuple(accepted),
            metrics=final_metrics,
            rejection_counts=rejection,
        )

    @staticmethod
    def _failure(
        code: CollectorFailureCode,
        metrics: CollectionMetrics | None = None,
        *,
        rejection_counts: RejectionCounts | None = None,
        retryable: bool = False,
        http_status: int | None = None,
        stop_code: CollectionStopCode | None = None,
    ) -> CollectionFailure:
        rejections = rejection_counts or RejectionCounts()
        safe_metrics = metrics or CollectionMetrics()
        safe_metrics = replace(
            safe_metrics,
            rejected_items=rejections.rejected_items,
            duplicate_items=rejections.duplicate_items,
        )
        return CollectionFailure(
            status="failed",
            error_code=code,
            metrics=safe_metrics,
            rejection_counts=rejections,
            retryable=retryable,
            http_status=http_status,
            stop_code=stop_code,
        )


def _job_values(item: Any, source_name: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("item is not an object")
    provider_id = item.get("id")
    title = item.get("jobTitle")
    company = item.get("companyName")
    url = item.get("url")
    location = item.get("jobGeo")
    description = item.get("jobDescription")
    if not isinstance(provider_id, (str, int)) or not str(provider_id).strip():
        raise ValueError("missing provider id")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (title, company, url, location, description)
    ):
        raise ValueError("missing required Jobicy field")
    assert isinstance(title, str)
    assert isinstance(company, str)
    assert isinstance(url, str)
    assert isinstance(location, str)
    assert isinstance(description, str)
    published = item.get("pubDate")
    published_at: datetime | None = None
    if published is not None:
        if not isinstance(published, str):
            raise ValueError("invalid publication date")
        try:
            published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if published_at.tzinfo is None:
                published_at = published_at.replace(tzinfo=UTC)
            published_at = published_at.astimezone(UTC)
        except ValueError as exc:
            raise ValueError("invalid publication date") from exc
    external_id = str(provider_id).strip()
    return {
        "source": "jobicy",
        "external_id": external_id,
        "source_url": url.strip(),
        "application_url": url.strip(),
        "title": title.strip(),
        "company": company.strip(),
        "location": location.strip(),
        "description": description,
        "published_at": published_at,
        "structured_data": {
            "provider": "jobicy",
            "provider_id": external_id,
            "title": title.strip(),
            "company": company.strip(),
            "location": location.strip(),
            "published": published_at.isoformat() if published_at else None,
            "source_url": url.strip(),
            "application_url": url.strip(),
        },
        "collected_at": datetime.now(UTC),
    }


def _with_transfer(
    metrics: CollectionMetrics,
    transfer: Any,
    duration: float,
) -> CollectionMetrics:
    if transfer is None:
        return CollectionMetrics(
            logical_requests=metrics.logical_requests,
            logical_pages=metrics.logical_pages,
            wire_attempts=metrics.wire_attempts,
            retries=metrics.retries,
            wire_bytes=metrics.wire_bytes,
            decoded_bytes=metrics.decoded_bytes,
            provider_items=metrics.provider_items,
            overflow_probe_items=metrics.overflow_probe_items,
            accepted_items=metrics.accepted_items,
            rejected_items=metrics.rejected_items,
            duplicate_items=metrics.duplicate_items,
            canonical_batch_bytes=metrics.canonical_batch_bytes,
            duration_seconds=max(0.0, duration),
        )
    return CollectionMetrics(
        logical_requests=metrics.logical_requests,
        logical_pages=metrics.logical_pages,
        wire_attempts=transfer.wire_attempts,
        retries=transfer.retries,
        wire_bytes=transfer.wire_bytes,
        decoded_bytes=transfer.decoded_bytes,
        provider_items=metrics.provider_items,
        overflow_probe_items=metrics.overflow_probe_items,
        accepted_items=metrics.accepted_items,
        rejected_items=metrics.rejected_items,
        duplicate_items=metrics.duplicate_items,
        canonical_batch_bytes=metrics.canonical_batch_bytes,
        duration_seconds=max(0.0, duration),
    )


def _stop_code(value: str | None) -> CollectionStopCode | None:
    if value is None:
        return None
    try:
        return CollectionStopCode(value)
    except ValueError:
        return None
