"""Canonical private snapshot materialization and tamper verification."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

from role_radar.evaluation.controlled_acquisition.contracts import (
    DatasetItem,
    SelectedCandidate,
)
from role_radar.evaluation.controlled_acquisition.manifest import sanitized_manifest
from role_radar.evaluation.controlled_acquisition.protocols import SNAPSHOT_VERSION
from role_radar.evaluation.controlled_acquisition.selection import blind_order
from role_radar.evaluation.snapshot_store import (
    SnapshotStore as _SnapshotStore,
)
from role_radar.evaluation.snapshot_store import (
    _json,
    canonical_line,
    sha256_bytes,
)

SnapshotStore = _SnapshotStore


def opaque_label_id(dataset_seed: str, cluster_id: str) -> str:
    return hashlib.sha256(
        f"{SNAPSHOT_VERSION}:label-id:{dataset_seed}:{cluster_id}".encode()
    ).hexdigest()[:24]


def materialize_records(
    items: tuple[DatasetItem, ...], *, dataset_seed: str
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    """Create the three ordered line streams without leaking selection metadata."""
    dataset_lines: list[bytes] = []
    provenance_lines: list[bytes] = []
    label_records: dict[str, dict[str, Any]] = {}
    for item in items:
        dataset_lines.append(canonical_line(item.__dict__ if hasattr(item, "__dict__") else {
            "ordinal": item.ordinal,
            "opaque_id": item.opaque_id,
            "title": item.title,
            "company": item.company,
            "location": item.location,
            "description": item.description,
            "source_url": item.source_url,
            "application_url": item.application_url,
            "provider_recency_at": item.provider_recency_at,
            "recency_semantic": item.recency_semantic,
            "selection_family": item.selection_family,
            "selection_reason": item.selection_reason,
        }))
        provenance_lines.append(
            canonical_line(
                {
                    "ordinal": item.ordinal,
                    "opaque_id": item.opaque_id,
                    "selection_family": item.selection_family,
                    "selection_reason": item.selection_reason,
                }
            )
        )
        label_records[item.opaque_id] = label_view_item(item)
    ordered_ids = blind_order(dataset_seed, label_records)
    label_lines = tuple(canonical_line(label_records[opaque_id]) for opaque_id in ordered_ids)
    return tuple(dataset_lines), tuple(provenance_lines), label_lines


def materialize_selection(
    selected: tuple[SelectedCandidate, ...], *, dataset_seed: str
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...]]:
    """Materialize full private records and all corresponding provenances."""
    items: list[DatasetItem] = []
    provenances: list[dict[str, Any]] = []
    for ordinal, selected_item in enumerate(selected, start=1):
        cluster = selected_item.cluster
        primary = cluster.primary
        opaque_id = opaque_label_id(dataset_seed, cluster.cluster_id)
        items.append(
            DatasetItem(
                ordinal=ordinal,
                opaque_id=opaque_id,
                title=primary.title,
                company=primary.company,
                location=primary.location,
                description=primary.description,
                source_url=primary.source_url,
                application_url=primary.application_url,
                provider_recency_at=primary.provider_recency_at,
                recency_semantic=primary.recency_semantic,
                selection_family=selected_item.selection_family,
                selection_reason=selected_item.selection_reason,
            )
        )
        provenances.append(
            {
                "ordinal": ordinal,
                "opaque_id": opaque_id,
                "provenances": [
                    {
                        "source_family": observation.source_family,
                        "source_id": observation.source_id,
                        "source_key": observation.source_key,
                        "source_revision": observation.source_revision,
                        "configuration_version": observation.configuration_version,
                        "external_id": observation.external_id,
                        "source_url": observation.source_url,
                        "application_url": observation.application_url,
                        "collected_at": observation.collected_at,
                    }
                    for observation in cluster.observations
                ],
            }
        )
    dataset_lines, _, label_lines = materialize_records(
        tuple(items), dataset_seed=dataset_seed
    )
    provenance_lines = tuple(canonical_line(item) for item in provenances)
    return dataset_lines, provenance_lines, label_lines


def semantic_dataset_sha256(
    *,
    header: Mapping[str, Any],
    dataset_lines: Iterable[bytes],
    provenance_lines: Iterable[bytes],
    label_lines: Iterable[bytes],
) -> str:
    payload = bytearray()
    payload.extend(_json({"snapshot_version": SNAPSHOT_VERSION, "header": dict(header)}))
    for group in (dataset_lines, provenance_lines, label_lines):
        for line in group:
            payload.extend(hashlib.sha256(line).digest())
    return sha256_bytes(bytes(payload))


def label_view_item(item: DatasetItem) -> dict[str, Any]:
    return {
        "opaque_id": item.opaque_id,
        "title": item.title,
        "company": item.company,
        "location": item.location,
        "description": item.description,
    }


def external_projection(internal: Mapping[str, Any]) -> dict[str, Any]:
    return sanitized_manifest(internal)
