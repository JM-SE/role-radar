"""Direct collector adapter seam; never imports the normal persistence writer."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from role_radar.collectors.outcomes import CollectionFailure, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.domain.dto import RawJob
from role_radar.evaluation.controlled_acquisition.contracts import Observation
from role_radar.evaluation.controlled_acquisition.recency import (
    parse_timestamp,
    provider_recency,
)


class CollectorAdapter(Protocol):
    async def __call__(
        self, snapshot: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionSuccess | CollectionFailure: ...


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
        description=raw.description,
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
    tasks: Iterable[tuple[SourceSnapshot, CollectorAdapter]],
    runtime: CollectorRuntime,
) -> tuple[Observation, ...]:
    observations: list[Observation] = []
    for snapshot, collector in tasks:
        result = await collector(snapshot, runtime)
        if isinstance(result, CollectionFailure):
            continue
        observations.extend(
            observation_from_raw(
                raw,
                source_id=snapshot.source_id,
                source_key=snapshot.source_key or snapshot.name,
                source_revision=0,
                configuration_version=snapshot.configuration_version,
            )
            for raw in result.jobs
        )
    return tuple(observations)
