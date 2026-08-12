"""Strong identity and weak-conflict clustering for the sealed candidate pool."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from role_radar.evaluation.controlled_acquisition.contracts import (
    CandidateCluster,
    Exclusion,
    HistoricalIdentity,
    Observation,
)
from role_radar.evaluation.controlled_acquisition.protocols import IDENTITY_VERSION
from role_radar.normalization.text import normalize_company, normalize_location, normalize_title
from role_radar.normalization.urls import TRACKING_PARAMS


def normalize_identity_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return None
    query = [
        (key.lower(), item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if key.lower() not in TRACKING_PARAMS and not key.lower().startswith("utm_")
    ]
    host = parsed.hostname.lower()
    port = parsed.port
    netloc = host if port in (None, 443) else f"{host}:{port}"
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit(("https", netloc, path, urlencode(sorted(query)), ""))


def _weak_keys(observation: Observation) -> tuple[str, ...]:
    values = "\x1f".join(
        (
            normalize_company(observation.company),
            normalize_title(observation.title),
            normalize_location(observation.location)[1] or "",
        )
    )
    keys = [hashlib.sha256(f"{IDENTITY_VERSION}:weak:ctl:{values}".encode()).hexdigest()]
    description = _description_key(observation)
    if description:
        keys.append(f"{IDENTITY_VERSION}:weak:description:{description}")
    return tuple(keys)


def _description_key(observation: Observation) -> str | None:
    if not observation.description:
        return None
    return hashlib.sha256(observation.description.strip().encode("utf-8")).hexdigest()


def strong_keys(observation: Observation) -> tuple[str, ...]:
    keys = [
        f"source:{observation.source_family}:{observation.source_key}:{observation.external_id}",
    ]
    for label, value in (
        ("official", normalize_identity_url(observation.source_url)),
        ("application", normalize_identity_url(observation.application_url)),
    ):
        if value:
            keys.append(f"{label}:{value}")
    return tuple(sorted(set(keys)))


@dataclass(frozen=True, slots=True)
class DeduplicationResult:
    clusters: tuple[CandidateCluster, ...]
    exclusions: tuple[Exclusion, ...]


class _UnionFind:
    def __init__(self, count: int) -> None:
        self.parent = list(range(count))

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def build_inventory_index(items: tuple[HistoricalIdentity, ...]) -> frozenset[str]:
    values: set[str] = set()
    for item in items:
        values.update(
            key
            for key in (
                f"source:{item.source_family}:{item.source_key}:{item.external_id}"
                if item.external_id
                else None,
                f"official:{item.official_url}" if item.official_url else None,
                f"application:{item.application_url}" if item.application_url else None,
            )
            if key
        )
    return frozenset(values)


def cluster_observations(
    observations: tuple[Observation, ...],
    *,
    historical_keys: frozenset[str] = frozenset(),
) -> DeduplicationResult:
    exclusions: list[Exclusion] = []
    eligible: list[Observation] = []
    for observation in observations:
        keys = strong_keys(observation)
        historical = next((key for key in keys if key in historical_keys), None)
        if historical is not None:
            exclusions.append(Exclusion(observation.external_id, "historical_strong_identity"))
        else:
            eligible.append(observation)

    union = _UnionFind(len(eligible))
    key_to_index: dict[str, int] = {}
    for index, observation in enumerate(eligible):
        for key in strong_keys(observation):
            previous = key_to_index.get(key)
            if previous is not None:
                union.union(previous, index)
            else:
                key_to_index[key] = index

    groups: dict[int, list[Observation]] = defaultdict(list)
    for index, observation in enumerate(eligible):
        groups[union.find(index)].append(observation)

    clusters: list[CandidateCluster] = []
    for members in groups.values():
        ordered = tuple(sorted(members, key=lambda item: (item.source_family, item.external_id)))
        keys = tuple(sorted({key for item in ordered for key in strong_keys(item)}))
        weak_groups = {_weak_key for item in ordered for _weak_key in _weak_keys(item)}
        clusters.append(
            CandidateCluster(
                cluster_id=hashlib.sha256(
                    f"{IDENTITY_VERSION}:cluster:{'|'.join(keys)}".encode()
                ).hexdigest(),
                observations=ordered,
                strong_keys=keys,
                weak_conflict=len(weak_groups) > 1 and len(ordered) > 1,
            )
        )

    # Weak matches are intentionally not merged.  If two independent clusters
    # share a weak fingerprint, exclude both rather than choosing one live.
    weak_members: dict[str, list[str]] = defaultdict(list)
    for cluster in clusters:
        for observation in cluster.observations:
            for key in _weak_keys(observation):
                weak_members[key].append(cluster.cluster_id)
    conflicted: set[str] = {
        cluster_id
        for members in weak_members.values()
        if len(set(members)) > 1
        for cluster_id in set(members)
    }
    final_clusters = tuple(
        sorted(
            (
                CandidateCluster(
                    cluster.cluster_id,
                    cluster.observations,
                    cluster.strong_keys,
                    cluster.weak_conflict or cluster.cluster_id in conflicted,
                )
                for cluster in clusters
                if cluster.cluster_id not in conflicted
            ),
            key=lambda item: item.cluster_id,
        )
    )
    exclusions.extend(
        Exclusion(cluster_id, "weak_identity_conflict") for cluster_id in sorted(conflicted)
    )
    return DeduplicationResult(final_clusters, tuple(exclusions))
