"""Thin offline-first orchestration for controlled acquisition."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from role_radar.evaluation.controlled_acquisition.configuration import ControlledAcquisitionConfig
from role_radar.evaluation.controlled_acquisition.contracts import (
    DatasetResult,
    Exclusion,
    Observation,
)
from role_radar.evaluation.controlled_acquisition.deduplication import cluster_observations
from role_radar.evaluation.controlled_acquisition.recency import eligibility
from role_radar.evaluation.controlled_acquisition.selection import select_clusters, selection_seed


class ObservationProvider(Protocol):
    async def acquire(self) -> tuple[Observation, ...]: ...


def seal_and_select(
    observations: tuple[Observation, ...],
    *,
    config: ControlledAcquisitionConfig,
    selection_as_of_utc: datetime,
    profile_sha256: str,
    historical_keys: frozenset[str] = frozenset(),
) -> DatasetResult:
    window = config.window(selection_as_of_utc)
    eligible_observations: list[Observation] = []
    exclusions = []
    for observation in observations:
        reason = eligibility(
            observation,
            cutoff_utc=window.cutoff_utc,
            as_of_utc=window.selection_as_of_utc,
            future_tolerance_seconds=config.future_tolerance_seconds,
        )
        if reason is not None:
            exclusions.append((observation.external_id, reason))
        else:
            eligible_observations.append(observation)
    dedup = cluster_observations(tuple(eligible_observations), historical_keys=historical_keys)
    seed = selection_seed(
        profile_sha256=profile_sha256,
        cutoff_utc=window.cutoff_utc.isoformat(),
        as_of_utc=window.selection_as_of_utc.isoformat(),
    )
    result = select_clusters(dedup.clusters, seed=seed)
    return DatasetResult(
        result.status,
        result.selected,
        result.target_counts,
        result.actual_counts,
        result.deficit_counts,
        result.fallback_count,
        tuple(
            [*dedup.exclusions, *(Exclusion(identity, reason) for identity, reason in exclusions)]
        ),
    )
