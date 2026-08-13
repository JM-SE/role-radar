"""Permutation-stable quota assignment and blind-view ordering."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable

from role_radar.evaluation.controlled_acquisition.contracts import (
    CandidateCluster,
    DatasetResult,
    SelectedCandidate,
)
from role_radar.evaluation.controlled_acquisition.protocols import (
    SELECTION_VERSION,
    TARGETS,
)


def selection_seed(
    *, profile_sha256: str, cutoff_utc: str, as_of_utc: str, protocol: str = SELECTION_VERSION
) -> str:
    value = f"{protocol}\x00{profile_sha256}\x00{cutoff_utc}\x00{as_of_utc}"
    return hashlib.sha256(value.encode()).hexdigest()


def _order(seed: str, cluster: CandidateCluster) -> str:
    return hashlib.sha256(
        f"{SELECTION_VERSION}:order:{seed}:{cluster.cluster_id}".encode()
    ).hexdigest()


def _matching(
    clusters: tuple[CandidateCluster, ...], seed: str, targets: dict[str, int]
) -> dict[str, str]:
    ordered = tuple(sorted(clusters, key=lambda item: _order(seed, item)))
    slots = [
        (family, index)
        for family, count in targets.items()
        for index in range(count)
    ]
    owners: dict[str, str] = {}

    def visit(cluster: CandidateCluster, seen: set[str]) -> bool:
        for family in sorted(cluster.families, key=lambda item: (_order(seed, cluster), item)):
            for slot_family, slot_index in slots:
                if slot_family != family:
                    continue
                slot_key = f"{slot_family}:{slot_index}"
                if slot_key in seen:
                    continue
                seen.add(slot_key)
                owner = owners.get(slot_key)
                if owner is None or visit(
                    next(item for item in ordered if item.cluster_id == owner), seen
                ):
                    owners[slot_key] = cluster.cluster_id
                    return True
        return False

    for cluster in ordered:
        visit(cluster, set())
    assigned: dict[str, str] = {}
    for slot, cluster_id in owners.items():
        assigned.setdefault(cluster_id, slot.split(":", 1)[0])
    return assigned


def select_clusters(
    clusters: Iterable[CandidateCluster], *, seed: str, targets: dict[str, int] | None = None
) -> DatasetResult:
    """Select the required total with soft family preferences.

    Matching first fills as many preferred family slots as possible.  Any
    remaining records are selected from the same deterministic order and are
    assigned to the family with the largest remaining deficit.  Therefore a
    family target is never a hard eligibility gate, while the resulting
    deficit/fallback accounting remains meaningful for multi-source clusters.
    """
    requested = dict(targets or TARGETS)
    if any(count < 0 for count in requested.values()):
        raise ValueError("selection targets must be non-negative")
    ordered = tuple(sorted(clusters, key=lambda item: _order(seed, item)))
    required_count = sum(requested.values())
    if len(ordered) < required_count:
        return DatasetResult(
            status="failed_insufficient",
            selected=(),
            target_counts=requested,
            actual_counts=Counter(),
            deficit_counts=requested,
            fallback_count=0,
        )

    assigned = _matching(ordered, seed, requested)
    chosen: list[SelectedCandidate] = [
        SelectedCandidate(cluster, family, "quota")
        for cluster in ordered
        if (family := assigned.get(cluster.cluster_id)) is not None
    ]
    selected_ids = {item.cluster.cluster_id for item in chosen}
    remaining = [cluster for cluster in ordered if cluster.cluster_id not in selected_ids]
    actual = Counter(item.selection_family for item in chosen)
    for cluster in remaining:
        if len(chosen) >= required_count:
            break
        family = min(
            cluster.families,
            key=lambda candidate_family: (
                -(requested.get(candidate_family, 0) - actual.get(candidate_family, 0)),
                candidate_family,
            ),
        )
        chosen.append(SelectedCandidate(cluster, family, "fallback"))
        actual[family] += 1
    deficits = {family: max(0, requested[family] - actual.get(family, 0)) for family in requested}
    if len(chosen) < sum(requested.values()):
        return DatasetResult(
            status="failed_insufficient",
            selected=(),
            target_counts=requested,
            actual_counts=dict(actual),
            deficit_counts=deficits,
            fallback_count=0,
        )
    return DatasetResult(
        status="selected",
        selected=tuple(chosen),
        target_counts=requested,
        actual_counts=dict(actual),
        deficit_counts=deficits,
        fallback_count=sum(item.selection_reason == "fallback" for item in chosen),
    )


def blind_order(seed: str, opaque_ids: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            opaque_ids,
            key=lambda value: hashlib.sha256(
                f"{SELECTION_VERSION}:blind:{seed}:{value}".encode()
            ).hexdigest(),
        )
    )
