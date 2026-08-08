"""Bounded Lever v1 postings collector.

The adapter owns only pagination, regional URL validation and provider mapping.
HTTP bounds, retry, TLS, redirect and budget policy are provided by F8.2's
``BoundedHttpClient``.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from role_radar.collectors.bounded_http import BoundedHttpClient, BoundedHttpError
from role_radar.collectors.bounded_json import BoundedJsonError, canonical_json_bytes, loads_bounded
from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionMetrics,
    CollectionStopCode,
    CollectionSuccess,
    CollectorFailureCode,
    RejectionCounts,
)
from role_radar.collectors.policy import LEVER_EU_HTTP_ORIGIN, LEVER_POLICY, CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.raw_job_bounds import CanonicalBatch, RawJobBoundsError, validate_raw_job
from role_radar.domain.dto import RawJob
from role_radar.sources.configuration import LeverRegion, LeverSourceConfigV1

_GLOBAL_HOST = "jobs.lever.co"
_EU_HOST = "jobs.eu.lever.co"
_DATA_PAGE_SIZE = 100
_MAX_DATA_PAGES = 5
_INVALID_JSON = object()


class LeverCollector:
    """Collect Lever postings using one fixed origin selected by region."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Any = time.monotonic,
        sleeper: Any = asyncio.sleep,
        budget: CollectionRunBudget | None = None,
        user_agent: str = "role-radar/0.1 (+homelab)",
        config: LeverSourceConfigV1 | None = None,
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
            config = self._config or LeverSourceConfigV1.model_validate(
                dict(snapshot.configuration)
            )
        except (TypeError, ValueError):
            return self._failure(CollectorFailureCode.CONFIG, CollectionMetrics())

        runtime_clock = runtime.clock
        start = runtime_clock()
        budget = runtime.budget or self._budget or CollectionRunBudget()
        policy = replace(
            LEVER_POLICY,
            http=replace(
                LEVER_POLICY.http,
                origin=(
                    LEVER_EU_HTTP_ORIGIN
                    if config.region is LeverRegion.EU
                    else LEVER_POLICY.http.origin
                ),
            ),
        )
        metrics = CollectionMetrics()
        rejection = RejectionCounts()
        accepted: list[RawJob] = []
        seen: dict[str, bytes] = {}
        page_signatures: set[str] = set()
        batch = CanonicalBatch(policy.batch_limit_bytes)
        data_items = 0

        try:
            async with BoundedHttpClient(
                policy.http,
                transport=runtime.transport or self._transport,
                clock=runtime_clock,
                sleeper=runtime.sleeper,
                budget=budget,
                user_agent=self._user_agent,
            ) as http:
                for page_number in range(_MAX_DATA_PAGES):
                    skip = page_number * _DATA_PAGE_SIZE
                    metrics = replace(
                        metrics,
                        logical_requests=metrics.logical_requests + 1,
                        logical_pages=metrics.logical_pages + 1,
                    )
                    page, metrics = await self._get_page(
                        http,
                        snapshot,
                        config,
                        runtime_clock,
                        start,
                        metrics,
                        limit=_DATA_PAGE_SIZE,
                        skip=skip,
                    )
                    if page is None:
                        return self._failure(
                            CollectorFailureCode.INTERNAL,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                        )
                    if page is _INVALID_JSON:
                        return self._failure(
                            CollectorFailureCode.INVALID_JSON,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                        )
                    if not isinstance(page, list):
                        return self._failure(
                            CollectorFailureCode.PAYLOAD_INVALID,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                            stop_code=CollectionStopCode.INVALID_PAYLOAD,
                        )
                    if len(page) > _DATA_PAGE_SIZE:
                        return self._failure(
                            CollectorFailureCode.JOB_LIMIT,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                            stop_code=CollectionStopCode.JOB_LIMIT_REACHED,
                        )
                    data_items += len(page)
                    if page:
                        try:
                            signature = hashlib.sha256(canonical_json_bytes(page)).hexdigest()
                        except (TypeError, ValueError):
                            return self._failure(
                                CollectorFailureCode.PAYLOAD_INVALID,
                                self._atomic_metrics(metrics, data_items),
                                rejection_counts=rejection,
                                stop_code=CollectionStopCode.INVALID_PAYLOAD,
                            )
                        if signature in page_signatures:
                            return self._failure(
                                CollectorFailureCode.PAYLOAD_INVALID,
                                self._atomic_metrics(metrics, data_items),
                                rejection_counts=rejection,
                                stop_code=CollectionStopCode.INVALID_PAYLOAD,
                                pagination_loop=True,
                            )
                        page_signatures.add(signature)

                    before = len(seen)
                    rejection, mapping_error = self._map_page(
                        snapshot,
                        config,
                        page,
                        accepted,
                        seen,
                        rejection,
                        batch,
                        runtime_clock,
                    )
                    if mapping_error is not None:
                        code, stop = mapping_error
                        return self._failure(
                            code,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                            stop_code=stop,
                        )
                    if len(page) == 0 or len(page) < _DATA_PAGE_SIZE:
                        break
                    if len(seen) == before:
                        return self._failure(
                            CollectorFailureCode.PAYLOAD_INVALID,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                            stop_code=CollectionStopCode.INVALID_PAYLOAD,
                            pagination_loop=True,
                        )
                else:
                    metrics = replace(
                        metrics,
                        logical_requests=metrics.logical_requests + 1,
                        logical_pages=metrics.logical_pages + 1,
                    )
                    probe, metrics = await self._get_page(
                        http,
                        snapshot,
                        config,
                        runtime_clock,
                        start,
                        metrics,
                        limit=1,
                        skip=500,
                    )
                    if probe is None:
                        return self._failure(
                            CollectorFailureCode.INTERNAL,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                        )
                    if probe is _INVALID_JSON:
                        return self._failure(
                            CollectorFailureCode.INVALID_JSON,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                        )
                    if not isinstance(probe, list):
                        return self._failure(
                            CollectorFailureCode.PAYLOAD_INVALID,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                            stop_code=CollectionStopCode.INVALID_PAYLOAD,
                        )
                    if probe:
                        metrics = replace(metrics, overflow_probe_items=1)
                        return self._failure(
                            CollectorFailureCode.JOB_LIMIT,
                            self._atomic_metrics(metrics, data_items),
                            rejection_counts=rejection,
                            stop_code=CollectionStopCode.JOB_LIMIT_REACHED,
                        )

            elapsed = max(0.0, runtime_clock() - start)
            final_metrics = replace(
                metrics,
                provider_items=data_items,
                accepted_items=len(accepted),
                rejected_items=rejection.rejected_items,
                duplicate_items=rejection.duplicate_items,
                canonical_batch_bytes=batch.size,
                duration_seconds=elapsed,
            )
            if data_items and not accepted:
                return self._failure(
                    CollectorFailureCode.NO_VALID_ITEMS,
                    final_metrics,
                    rejection_counts=rejection,
                    stop_code=CollectionStopCode.NO_VALID_ITEMS,
                )
            status: Literal["ok", "partial"] = (
                "partial"
                if rejection.invalid_item or rejection.oversized_item or rejection.duplicate_items
                else "ok"
            )
            return CollectionSuccess(
                status=status,
                jobs=tuple(accepted),
                metrics=final_metrics,
                rejection_counts=rejection,
            )
        except BoundedHttpError as exc:
            transfer = exc.metrics
            failed = replace(
                self._atomic_metrics(metrics, data_items),
                wire_attempts=metrics.wire_attempts + transfer.wire_attempts,
                retries=metrics.retries + transfer.retries,
                wire_bytes=metrics.wire_bytes + transfer.wire_bytes,
                decoded_bytes=metrics.decoded_bytes + transfer.decoded_bytes,
                duration_seconds=max(0.0, runtime_clock() - start),
            )
            return self._failure(
                exc.code,
                failed,
                rejection_counts=rejection,
                retryable=exc.retryable,
                http_status=exc.http_status,
                stop_code=self._stop_code(exc.stop_code),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return self._failure(
                CollectorFailureCode.INTERNAL,
                self._atomic_metrics(metrics, data_items),
                rejection_counts=rejection,
            )

    async def _get_page(
        self,
        http: BoundedHttpClient,
        snapshot: SourceSnapshot,
        config: LeverSourceConfigV1,
        clock: Any,
        start: float,
        metrics: CollectionMetrics,
        *,
        limit: int,
        skip: int,
    ) -> tuple[Any, CollectionMetrics]:
        remaining = max(0.0, LEVER_POLICY.http.source_deadline_seconds - (clock() - start))
        response = await http.get(
            f"/v0/postings/{config.site}",
            query=(("mode", "json"), ("limit", str(limit)), ("skip", str(skip))),
            deadline_seconds=remaining,
        )
        next_metrics = replace(
            metrics,
            wire_attempts=metrics.wire_attempts + response.metrics.wire_attempts,
            retries=metrics.retries + response.metrics.retries,
            wire_bytes=metrics.wire_bytes + response.metrics.wire_bytes,
            decoded_bytes=metrics.decoded_bytes + response.metrics.decoded_bytes,
            duration_seconds=max(0.0, clock() - start),
        )
        if clock() - start >= LEVER_POLICY.http.source_deadline_seconds:
            raise BoundedHttpError(
                CollectorFailureCode.DEADLINE,
                metrics=response.metrics,
                stop_code=CollectionStopCode.DEADLINE_EXPIRED.value,
            )
        try:
            payload = loads_bounded(
                response.body,
                max_depth=LEVER_POLICY.json_max_depth,
                max_nodes=LEVER_POLICY.json_max_nodes,
            )
        except BoundedJsonError:
            return _INVALID_JSON, next_metrics
        return payload, next_metrics

    def _map_page(
        self,
        snapshot: SourceSnapshot,
        config: LeverSourceConfigV1,
        page: list[Any],
        accepted: list[RawJob],
        seen: dict[str, bytes],
        rejection: RejectionCounts,
        batch: CanonicalBatch,
        clock: Any,
    ) -> tuple[RejectionCounts, tuple[CollectorFailureCode, CollectionStopCode] | None]:
        for item in page:
            try:
                raw = self._raw_values(item, snapshot, config, clock)
                canonical = validate_raw_job(
                    raw,
                    description_limit_bytes=LEVER_POLICY.description_limit_bytes,
                    structured_data_limit_bytes=LEVER_POLICY.structured_data_limit_bytes,
                    max_depth=LEVER_POLICY.json_max_depth,
                )
                external_id = raw.external_id
                if external_id in seen:
                    if seen[external_id] == canonical_json_bytes(
                        raw.model_dump(mode="json", exclude={"collected_at"})
                    ):
                        rejection = replace(
                            rejection, duplicate_identical=rejection.duplicate_identical + 1
                        )
                    else:
                        rejection = replace(
                            rejection, duplicate_conflict=rejection.duplicate_conflict + 1
                        )
                    continue
                batch.add(canonical)
                seen[external_id] = canonical_json_bytes(
                    raw.model_dump(mode="json", exclude={"collected_at"})
                )
                accepted.append(raw)
            except RawJobBoundsError as exc:
                if exc.kind == "batch":
                    return rejection, (
                        CollectorFailureCode.BATCH_LIMIT,
                        CollectionStopCode.BATCH_LIMIT_REACHED,
                    )
                rejection = replace(
                    rejection,
                    invalid_item=rejection.invalid_item + (exc.kind == "invalid"),
                    oversized_item=rejection.oversized_item + (exc.kind == "oversized"),
                )
            except (TypeError, ValueError):
                rejection = replace(rejection, invalid_item=rejection.invalid_item + 1)
        return rejection, None

    @staticmethod
    def _raw_values(
        item: Any, snapshot: SourceSnapshot, config: LeverSourceConfigV1, clock: Any
    ) -> RawJob:
        if not isinstance(item, dict):
            raise RawJobBoundsError("invalid")
        item_id = item.get("id")
        if (
            isinstance(item_id, bool)
            or not isinstance(item_id, (str, int))
            or not str(item_id).strip()
        ):
            raise RawJobBoundsError("invalid")
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            raise RawJobBoundsError("invalid")
        hosted = LeverCollector._regional_url(item.get("hostedUrl"), config.region, required=True)
        apply = LeverCollector._regional_url(item.get("applyUrl"), config.region, required=False)
        categories = item.get("categories")
        if categories is not None and not isinstance(categories, dict):
            raise RawJobBoundsError("invalid")
        location: str | None = None
        if isinstance(categories, dict):
            primary = categories.get("location")
            if primary is not None and (not isinstance(primary, str) or not primary.strip()):
                if primary is not None:
                    raise RawJobBoundsError("invalid")
            elif isinstance(primary, str):
                location = primary.strip()
        all_locations = item.get("allLocations")
        if all_locations is not None and not isinstance(all_locations, list):
            raise RawJobBoundsError("invalid")
        if location is None and isinstance(all_locations, list):
            values = [
                value.strip()
                for value in all_locations
                if isinstance(value, str) and value.strip()
            ]
            location = ", ".join(values) or None
        description_plain = item.get("descriptionPlain")
        description_html = item.get("description")
        if description_plain is not None and not isinstance(description_plain, str):
            raise RawJobBoundsError("invalid")
        if description_html is not None and not isinstance(description_html, str):
            raise RawJobBoundsError("invalid")
        description = (
            description_plain.strip()
            if isinstance(description_plain, str) and description_plain.strip()
            else description_html
        )
        structured = {
            key: item[key]
            for key in (
                "id",
                "text",
                "categories",
                "country",
                "workplaceType",
                "salaryRange",
                "hostedUrl",
                "applyUrl",
                "allLocations",
            )
            if key in item
        }
        return RawJob(
            source="lever",
            external_id=str(item_id),
            title=text,
            company=config.company or snapshot.name,
            location=location,
            description=description,
            source_url=hosted,
            application_url=apply or hosted,
            structured_data=structured,
            collected_at=datetime.now(UTC),
        )

    @staticmethod
    def _regional_url(value: Any, region: LeverRegion, *, required: bool) -> str | None:
        if value is None and not required:
            return None
        if not isinstance(value, str) or not value or any(char.isspace() for char in value):
            raise RawJobBoundsError("invalid")
        try:
            parsed = urlsplit(value)
            host = _EU_HOST if region is LeverRegion.EU else _GLOBAL_HOST
            if (
                parsed.scheme.lower() != "https"
                or parsed.hostname != host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
            ):
                raise RawJobBoundsError("invalid")
        except (TypeError, ValueError) as exc:
            raise RawJobBoundsError("invalid") from exc
        return value

    @staticmethod
    def _atomic_metrics(metrics: CollectionMetrics, provider_items: int) -> CollectionMetrics:
        return replace(
            metrics,
            provider_items=provider_items,
            accepted_items=0,
            canonical_batch_bytes=0,
            duration_seconds=max(0.0, metrics.duration_seconds),
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
        pagination_loop: bool = False,
    ) -> CollectionFailure:
        if pagination_loop:
            stop_code = CollectionStopCode.PAGINATION_LOOP
        rejections = rejection_counts or RejectionCounts()
        metrics = replace(
            metrics,
            rejected_items=rejections.rejected_items,
            duplicate_items=rejections.duplicate_items,
        )
        return CollectionFailure(
            status="failed",
            error_code=code,
            metrics=metrics,
            rejection_counts=rejections,
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
