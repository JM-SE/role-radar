"""Pure construction of the five F10.1C bundle files."""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from role_radar.evaluation.cohort_freeze.contracts import (
    CandidateEvidence,
    CorpusResult,
    DeploymentIdentity,
    PartitionResult,
    RepositorySnapshot,
    SelectionResult,
)
from role_radar.evaluation.cohort_freeze.partition import partition_rank_sha256
from role_radar.evaluation.cohort_freeze.policy import (
    BASELINE_PROFILE_ID,
    BASELINE_PROFILE_SCHEMA,
    BASELINE_PROFILE_SHA256,
    BASELINE_PROFILE_VERSION,
    CORPUS_COUNT,
    CORPUS_PROTOCOL,
    HOLDOUT_COUNT,
    INTERNAL_MANIFEST_SCHEMA_V2,
    MATERIALIZATION_PROTOCOL,
    MATERIALIZATION_PROTOCOL_V2,
    PARTITION_PROTOCOL,
    PILOT_COUNT,
    SNAPSHOT_SCHEMA,
    TARGET_COUNT,
    V2_DATASET_DOMAIN,
    canonical_hash,
    canonical_time,
)
from role_radar.evaluation.cohort_freeze.selection import item_semantic_sha256
from role_radar.evaluation.snapshot_store import canonical_line, sha256_bytes


def _opaque_id(dataset_id: str, semantic_hash: str) -> str:
    return hashlib.sha256(
        b"f10.1c:opaque-id-v1\0"
        + dataset_id.encode("ascii")
        + b"\0"
        + semantic_hash.encode("ascii")
    ).hexdigest()[:24]


def _blind_key(dataset_id: str, opaque_id: str) -> str:
    return hashlib.sha256(
        b"f10.1c:blind-order-v1\0" + dataset_id.encode("ascii") + b"\0" + opaque_id.encode("ascii")
    ).hexdigest()


def _source_projection(candidate: CandidateEvidence) -> dict[str, Any]:
    source = candidate.source_snapshot_json
    return {
        "source_id": source.get("source_id"),
        "source_key": source.get("source_key"),
        "type": source.get("type"),
        "revision": source.get("revision"),
        "snapshot_sha256": canonical_hash(source),
    }


def _provenance(candidate: CandidateEvidence, opaque_id: str, ordinal: int) -> dict[str, Any]:
    if candidate.accepted_observation_at is None or candidate.provider_recency_at is None:
        raise ValueError("materialization_timestamp_missing")
    identity = sorted(
        (
            item
            for item in candidate.identity_keys
            if item.version == candidate.identity_policy_version
        ),
        key=lambda item: (item.kind, item.version, item.value),
    )[0]
    return {
        "opaque_id": opaque_id,
        "job_id": candidate.job_id,
        "link_id": candidate.link_id,
        "run_id": candidate.run_id,
        "operation_id": candidate.operation_id,
        "ordinal": ordinal,
        "accepted_observation_at_utc": canonical_time(candidate.accepted_observation_at),
        "provider_recency_at": canonical_time(candidate.provider_recency_at),
        "recency_semantic": candidate.recency_semantic,
        "freshness_policy_version": candidate.freshness_policy_version,
        "identity_policy_version": candidate.identity_policy_version,
        "provenance_hash": candidate.provenance_hash,
        "provenance_scope": "source_key+external_id",
        "run_policy_version": candidate.run_policy_version,
        "run_snapshot_hash": candidate.run_snapshot_hash,
        "source_snapshot": _source_projection(candidate),
        "identity": {
            "kind": identity.kind,
            "version": identity.version,
            "value_digest": identity.value_digest,
        },
    }


def materialize(
    snapshot: RepositorySnapshot,
    selection: SelectionResult,
    *,
    deployment: DeploymentIdentity | None = None,
    frozen_at: datetime | None = None,
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], tuple[bytes, ...], dict[str, Any], str]:
    """Return dataset/provenance/label lines, internal manifest and dataset ID."""

    if selection.selected_count != TARGET_COUNT or len(selection.selected) != TARGET_COUNT:
        raise ValueError("materialization_requires_exactly_50")
    identity = deployment or DeploymentIdentity(alembic_head=snapshot.alembic_version)
    item_hashes = tuple(item_semantic_sha256(item) for item in selection.selected)
    preimage = {
        "schema_version": SNAPSHOT_SCHEMA,
        "materialization_protocol": MATERIALIZATION_PROTOCOL,
        "selection_protocol": "f10.1c-selection-v1",
        "profile": {
            "id": BASELINE_PROFILE_ID,
            "version": BASELINE_PROFILE_VERSION,
            "schema": BASELINE_PROFILE_SCHEMA,
            "sha256": BASELINE_PROFILE_SHA256,
        },
        "item_semantic_sha256": item_hashes,
    }
    dataset_id = sha256_bytes(b"f10.1c:dataset-id-v1\0" + canonical_line(preimage))
    opaque_ids = tuple(_opaque_id(dataset_id, value) for value in item_hashes)
    if len(set(opaque_ids)) != TARGET_COUNT:
        raise ValueError("opaque_id_collision")
    dataset_records: list[dict[str, Any]] = []
    provenance_records: list[dict[str, Any]] = []
    label_records: dict[str, dict[str, Any]] = {}
    for ordinal, (candidate, opaque_id) in enumerate(
        zip(selection.selected, opaque_ids, strict=True), start=1
    ):
        content = {
            "opaque_id": opaque_id,
            "ordinal": ordinal,
            "title": candidate.title,
            "company": candidate.company,
            "location": candidate.location,
            "description": candidate.description,
            "application_url": candidate.application_url,
        }
        dataset_records.append(content)
        provenance_records.append(_provenance(candidate, opaque_id, ordinal))
        label_records[opaque_id] = {
            key: content[key]
            for key in ("opaque_id", "title", "company", "location", "description")
        }
    dataset_lines = tuple(canonical_line(item) for item in dataset_records)
    provenance_lines = tuple(canonical_line(item) for item in provenance_records)
    label_lines = tuple(
        canonical_line(label_records[item])
        for item in sorted(label_records, key=lambda value: _blind_key(dataset_id, value))
    )
    frozen = (
        (frozen_at or datetime.now(UTC))
        .astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    internal = {
        "schema_version": SNAPSHOT_SCHEMA,
        "dataset_id": dataset_id,
        "count": TARGET_COUNT,
        "selection_protocol": "f10.1c-selection-v1",
        "materialization_protocol": MATERIALIZATION_PROTOCOL,
        "candidate_cohort_sha256": selection.candidate_cohort_sha256,
        "selection_sha256": selection.selection_sha256,
        "item_semantic_sha256": [
            {"opaque_id": opaque, "sha256": value}
            for opaque, value in zip(opaque_ids, item_hashes, strict=True)
        ],
        "dataset_sha256": sha256_bytes(b"".join(dataset_lines)),
        "provenance_sha256": sha256_bytes(b"".join(provenance_lines)),
        "label_view_sha256": sha256_bytes(b"".join(label_lines)),
        "semantic_root_sha256": selection.selection_sha256,
        "profile": {
            "id": BASELINE_PROFILE_ID,
            "version": BASELINE_PROFILE_VERSION,
            "schema": BASELINE_PROFILE_SCHEMA,
            "sha256": BASELINE_PROFILE_SHA256,
        },
        "deployment": {
            "code_commit": identity.code_commit,
            "clean": identity.clean,
            "alembic_head": identity.alembic_head,
        },
        "aggregates": {
            "source_types": dict(
                Counter(item.source_type or "unknown" for item in selection.selected)
            ),
            "run_count": len({item.run_id for item in selection.selected}),
        },
        "frozen_at": frozen,
        "preimage": preimage,
    }
    return dataset_lines, provenance_lines, label_lines, internal, dataset_id


materialize_selection = materialize
opaque_id = _opaque_id
blind_order_key = _blind_key


def _v2_opaque_id(dataset_id: str, item_hash: str) -> str:
    return hashlib.sha256(
        b"f10.1c:opaque-id-v2\0" + dataset_id.encode("ascii") + b"\0" + item_hash.encode("ascii")
    ).hexdigest()[:24]


def _v2_blind_key(dataset_id: str, split: str, opaque_id: str) -> str:
    return hashlib.sha256(
        b"f10.1c:blind-order-v2\0"
        + dataset_id.encode("ascii")
        + b"\0"
        + split.encode("ascii")
        + b"\0"
        + opaque_id.encode("ascii")
    ).hexdigest()


def materialize_v2(
    snapshot: RepositorySnapshot,
    corpus: CorpusResult,
    partition: PartitionResult,
    *,
    deployment: DeploymentIdentity | None = None,
    frozen_at: datetime | None = None,
) -> tuple[dict[str, bytes], dict[str, Any], str]:
    """Build the six-file v2 bundle payload without touching the filesystem."""

    if corpus.status != "ready" or corpus.corpus_sha256 is None:
        raise ValueError("corpus_not_ready")
    if (
        len(corpus.items) != CORPUS_COUNT
        or len(partition.pilot) != PILOT_COUNT
        or len(partition.holdout) != HOLDOUT_COUNT
    ):
        raise ValueError("materialization_cardinality_invalid")
    identity = deployment or DeploymentIdentity(alembic_head=snapshot.alembic_version)
    item_hashes = tuple(item.item_semantic_sha256 for item in corpus.items)
    preimage = {
        "schema_version": INTERNAL_MANIFEST_SCHEMA_V2,
        "corpus_protocol": CORPUS_PROTOCOL,
        "partition_protocol": PARTITION_PROTOCOL,
        "materialization_protocol": MATERIALIZATION_PROTOCOL_V2,
        "boundaries": {
            "lower": snapshot.boundary.run_id,
            "upper": snapshot.upper_boundary.run_id if snapshot.upper_boundary else None,
        },
        "profile": {
            "id": BASELINE_PROFILE_ID,
            "version": BASELINE_PROFILE_VERSION,
            "schema": BASELINE_PROFILE_SCHEMA,
            "sha256": BASELINE_PROFILE_SHA256,
        },
        "corpus_sha256": corpus.corpus_sha256,
        "pilot_sha256": partition.pilot_sha256,
        "holdout_sha256": partition.holdout_sha256,
        "quota_sha256": partition.quota_sha256,
        "item_semantic_sha256": item_hashes,
    }
    dataset_id = sha256_bytes(V2_DATASET_DOMAIN.encode("ascii") + b"\0" + canonical_line(preimage))
    opaque_by_key = {
        (item.item_semantic_sha256, item.strong_identity_digest): _v2_opaque_id(
            dataset_id, item.item_semantic_sha256
        )
        for item in corpus.items
    }
    if len(set(opaque_by_key.values())) != CORPUS_COUNT:
        raise ValueError("opaque_id_collision")
    pilot_keys = {
        (item.item_semantic_sha256, item.strong_identity_digest) for item in partition.pilot
    }
    holdout_keys = {
        (item.item_semantic_sha256, item.strong_identity_digest) for item in partition.holdout
    }

    corpus_records: list[dict[str, Any]] = []
    provenance_records: list[dict[str, Any]] = []
    item_manifest: list[dict[str, Any]] = []
    for ordinal, item in enumerate(corpus.items, start=1):
        key = (item.item_semantic_sha256, item.strong_identity_digest)
        opaque = opaque_by_key[key]
        candidate = item.evidence
        if candidate.accepted_observation_at is None or candidate.provider_recency_at is None:
            raise ValueError("materialization_timestamp_missing")
        corpus_records.append(
            {
                "opaque_id": opaque,
                "ordinal": ordinal,
                "title": candidate.title,
                "company": candidate.company,
                "location": candidate.location,
                "description": candidate.description,
                "application_url": candidate.application_url,
            }
        )
        provenance_records.append(
            {
                "opaque_id": opaque,
                "job_id": candidate.job_id,
                "link_id": candidate.link_id,
                "run_id": candidate.run_id,
                "operation_id": candidate.operation_id,
                "accepted_observation_at_utc": canonical_time(candidate.accepted_observation_at),
                "provider_recency_at": canonical_time(candidate.provider_recency_at),
                "recency_semantic": candidate.recency_semantic,
                "freshness_policy_version": candidate.freshness_policy_version,
                "identity_policy_version": candidate.identity_policy_version,
                "provenance_hash": candidate.provenance_hash,
                "provenance_scope": "source_key+external_id",
                "run_policy_version": candidate.run_policy_version,
                "run_snapshot_hash": candidate.run_snapshot_hash,
                "source_snapshot": _source_projection(candidate),
                "identity_digest": item.strong_identity_digest,
            }
        )
        split = "pilot" if key in pilot_keys else "holdout" if key in holdout_keys else ""
        if not split:
            raise ValueError("partition_membership_invalid")
        item_manifest.append(
            {
                "opaque_id": opaque,
                "item_semantic_sha256": item.item_semantic_sha256,
                "strong_identity_digest": item.strong_identity_digest,
                "source_stratum": item.source_stratum,
                "split": split,
                "partition_rank_sha256": partition_rank_sha256(corpus.corpus_sha256, item),
            }
        )

    corpus_lines = tuple(canonical_line(record) for record in corpus_records)
    provenance_lines = tuple(canonical_line(record) for record in provenance_records)

    def label_lines(items: tuple[Any, ...], split: str) -> bytes:
        records = []
        for item in items:
            opaque = opaque_by_key[(item.item_semantic_sha256, item.strong_identity_digest)]
            candidate = item.evidence
            records.append(
                (
                    _v2_blind_key(dataset_id, split, opaque),
                    canonical_line(
                        {
                            "opaque_id": opaque,
                            "title": candidate.title,
                            "company": candidate.company,
                            "location": candidate.location,
                            "description": candidate.description,
                        }
                    ),
                )
            )
        return b"".join(line for _key, line in sorted(records, key=lambda value: value[0]))

    pilot_lines = label_lines(partition.pilot, "pilot")
    holdout_lines = label_lines(partition.holdout, "holdout")
    frozen = (
        (frozen_at or datetime.now(UTC))
        .astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    file_payloads = {
        "corpus.jsonl": b"".join(corpus_lines),
        "provenance.jsonl": b"".join(provenance_lines),
        "pilot-label-view.jsonl": pilot_lines,
        "holdout-label-view.jsonl": holdout_lines,
    }
    internal = {
        "schema_version": INTERNAL_MANIFEST_SCHEMA_V2,
        "dataset_id": dataset_id,
        "boundaries": {
            "lower": {
                "run_id": snapshot.boundary.run_id,
                "started_at_utc": snapshot.boundary.started_at_utc,
                "inclusive": True,
            },
            "upper": {
                "run_id": snapshot.upper_boundary.run_id if snapshot.upper_boundary else None,
                "started_at_utc": (
                    snapshot.upper_boundary.started_at_utc if snapshot.upper_boundary else None
                ),
                "inclusive": True,
            },
        },
        "counts": {"corpus": CORPUS_COUNT, "pilot": PILOT_COUNT, "holdout": HOLDOUT_COUNT},
        "hashes": {
            "bounded_fingerprint_sha256": (
                snapshot.bounded_fingerprint_sha256 or snapshot.fingerprint
            ),
            "corpus_sha256": corpus.corpus_sha256,
            "pilot_sha256": partition.pilot_sha256,
            "holdout_sha256": partition.holdout_sha256,
            "quota_sha256": partition.quota_sha256,
        },
        "protocols": {
            "corpus": CORPUS_PROTOCOL,
            "partition": PARTITION_PROTOCOL,
            "materialization": MATERIALIZATION_PROTOCOL_V2,
        },
        "profile": preimage["profile"],
        "deployment": {
            "code_commit": identity.code_commit,
            "clean": identity.clean,
            "alembic_head": identity.alembic_head,
        },
        "source_quotas": [
            {
                "source_stratum": quota.source_stratum,
                "population": quota.population,
                "minimum_applied": quota.minimum_applied,
                "ideal": [quota.ideal_numerator, quota.ideal_denominator],
                "floor": quota.floor,
                "remainder": [quota.remainder_numerator, quota.remainder_denominator],
                "tie_break_sha256": quota.tie_break_sha256,
                "quota": quota.quota,
            }
            for quota in partition.quotas
        ],
        "items": item_manifest,
        "file_hashes": {name: sha256_bytes(value) for name, value in file_payloads.items()},
        "frozen_at": frozen,
        "preimage": preimage,
    }
    return file_payloads, internal, dataset_id


__all__ = [
    "blind_order_key",
    "materialize",
    "materialize_selection",
    "materialize_v2",
    "opaque_id",
]
