"""Direct collector adapter seam; never imports the normal persistence writer."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from role_radar.collectors.outcomes import CollectionFailure, CollectionOutcome, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import (
    CollectorContext,
    create_collector,
    validate_snapshot,
)
from role_radar.domain.dto import RawJob
from role_radar.evaluation.controlled_acquisition.contracts import Observation
from role_radar.evaluation.controlled_acquisition.protocols import PLAN_VERSION_V2
from role_radar.evaluation.controlled_acquisition.recency import (
    parse_timestamp,
    provider_recency,
)
from role_radar.evaluation.controlled_acquisition.source_plan import (
    SourcePlan,
)
from role_radar.normalization.text import html_to_text

_MAX_DESCRIPTION_BYTES = 256 * 1024


def _inert_description(value: str | None) -> str | None:
    if value is None:
        return None
    text = html_to_text(value)
    if len(text.encode("utf-8")) > _MAX_DESCRIPTION_BYTES:
        raise ValueError("description_limit")
    return text or None


class JournaledTransport(httpx.AsyncBaseTransport):
    """Record only opaque request intent/results around every wire attempt."""

    def __init__(
        self,
        *,
        operation_id: str,
        source_id: str,
        journal: Any,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._operation_id = operation_id
        self._source_id = source_id
        self._journal = journal
        self._ordinal = 0
        self._transport = transport or httpx.AsyncHTTPTransport(retries=0)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._ordinal += 1
        request_id = hashlib.sha256(
            f"{self._operation_id}:{self._source_id}:{self._ordinal}:"
            f"{request.method}:{request.url}".encode()
        ).hexdigest()
        self._journal.record_request_intent(
            operation_id=self._operation_id, request_id=request_id
        )
        try:
            response = await self._transport.handle_async_request(request)
        except Exception:
            self._journal.record_request_result(
                operation_id=self._operation_id, request_id=request_id
            )
            raise
        self._journal.record_request_result(
            operation_id=self._operation_id, request_id=request_id
        )
        return response

    async def aclose(self) -> None:
        await self._transport.aclose()


class CollectorAdapter(Protocol):
    async def __call__(
        self, snapshot: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionSuccess | CollectionFailure: ...


@dataclass(frozen=True, slots=True)
class CollectorTask:
    snapshot: SourceSnapshot
    source_revision: int
    collector: CollectorAdapter


@dataclass(frozen=True, slots=True)
class EphemeralCollectorTaskFactory:
    """Build collectors from verified plan-v2 configs without ORM source rows."""

    context: CollectorContext

    def build(self, plan: SourcePlan) -> tuple[CollectorTask, ...]:
        if plan.plan_version != PLAN_VERSION_V2:
            raise ValueError("plan_version_unsupported")
        tasks: list[CollectorTask] = []
        for item in plan.source_configs:
            family = str(item["family"])
            source_key = str(item["source_key"])
            source_id = f"ephemeral:{hashlib.sha256(source_key.encode()).hexdigest()[:32]}"
            snapshot = validate_snapshot(
                SourceSnapshot(
                    source_id=source_id,
                    source_type=family,
                    name=source_key,
                    configuration=dict(item["configuration"]),
                    source_key=source_key,
                    configuration_version=int(item["configuration_version"]),
                )
            )
            tasks.append(
                CollectorTask(
                    snapshot=snapshot,
                    source_revision=0,
                    collector=lambda current, runtime, context=self.context: _collect_direct(
                        current, runtime, context
                    ),
                )
            )
        return tuple(tasks)


async def _collect_direct(
    snapshot: SourceSnapshot, runtime: CollectorRuntime, context: CollectorContext
) -> CollectionOutcome:
    collector = create_collector(snapshot, context)
    return await collector.collect(snapshot, runtime)


def observation_from_raw(
    raw: RawJob,
    *,
    source_id: str,
    source_key: str,
    source_revision: int,
    configuration_version: int,
) -> Observation:
    family = raw.source.lower()
    recency, semantic = provider_recency(family, raw.structured_data, raw.published_at)
    return Observation(
        source_family=family,
        source_id=source_id,
        source_key=source_key,
        source_revision=source_revision,
        configuration_version=configuration_version,
        external_id=raw.external_id,
        title=raw.title,
        company=raw.company,
        location=raw.location,
        description=_inert_description(raw.description),
        source_url=raw.source_url,
        application_url=raw.application_url,
        provider_recency_at=recency,
        recency_semantic=semantic,
        provider_status=raw.structured_data.get("state")
        if isinstance(raw.structured_data.get("state"), str)
        else None,
        expires_at=parse_timestamp(raw.structured_data.get("expiresAt")),
        collected_at=raw.collected_at,
        structured_data={"provider": family},
    )


async def collect_sequential(
    tasks: Iterable[CollectorTask],
    runtime: CollectorRuntime,
    *,
    before_task: Callable[[CollectorTask], None] | None = None,
    after_task: Callable[[CollectorTask, CollectionOutcome], None] | None = None,
    runtime_factory: Callable[[CollectorTask], CollectorRuntime] | None = None,
) -> tuple[Observation, ...]:
    observations: list[Observation] = []
    for task in tasks:
        if before_task is not None:
            before_task(task)
        task_runtime = runtime_factory(task) if runtime_factory is not None else runtime
        result = await task.collector(task.snapshot, task_runtime)
        if after_task is not None:
            after_task(task, result)
        if isinstance(result, CollectionFailure):
            continue
        observations.extend(
            observation_from_raw(
                raw,
                source_id=task.snapshot.source_id,
                source_key=task.snapshot.source_key or task.snapshot.name,
                source_revision=task.source_revision,
                configuration_version=task.snapshot.configuration_version,
            )
            for raw in result.jobs
        )
    return tuple(observations)
