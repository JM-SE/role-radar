"""Manifests and checksums — sealed pool, pilot/holdout, dataset ID, blind order.

Sole F10.1F owner of manifests. Canonical bytes are strict JSON
(UTF-8, ensure_ascii=False, sorted keys, compact separators, no NaN)
bound under distinct domains. Checksums are SHA-256 hex. Dataset ID
and blind order reuse the approved F10.1E domains to hold payload
contracts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Final

from role_radar.evaluation.filesystem import sha256_bytes
from role_radar.evaluation.profile_relevance.hashing import (
    blind_order_key as _blind_order_key,
)
from role_radar.evaluation.profile_relevance.hashing import canonical_json_bytes
from role_radar.evaluation.profile_relevance.hashing import domain_hash as _domain_hash
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_BLIND_ORDER,
    DOMAIN_DATASET_ID,
)

SCHEMA_SEALED_POOL_MANIFEST: Final[str] = "f10.1f-sealed-pool-manifest-v1"
SCHEMA_DATASET_MANIFEST: Final[str] = "f10.1f-dataset-manifest-v1"
DOMAIN_SEALED_POOL_MANIFEST: Final[str] = "role-radar:f10.1f:sealed-pool-manifest:v1"
DOMAIN_DATASET_MANIFEST: Final[str] = "role-radar:f10.1f:dataset-manifest:v1"
DOMAIN_CHECKSUM: Final[str] = "role-radar:f10.1f:checksum:v1"


class ManifestError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ManifestError(code)
    if any(c not in "0123456789abcdef" for c in value):
        raise ManifestError(code)


def _canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ManifestError("manifest_canonical_invalid") from exc
    return text.encode("utf-8")


def _domain_hash_bytes(domain: str, canonical: bytes) -> str:
    if not domain.isascii():
        raise ManifestError("manifest_domain_invalid")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


@dataclass(frozen=True, slots=True)
class SealedPoolManifest:
    """Content-addressed sealed pool manifest."""

    dataset_id: str
    pool_sha256: str
    provenance_sha256: str
    source_plan_sha256: str
    inventory_sha256: str
    preview_input_sha256: str
    selection_sha256: str
    partition_sha256: str
    pilot_membership_sha256: str
    holdout_membership_sha256: str
    observation_count: int
    corpus_count: int
    pilot_count: int
    holdout_count: int
    canonical_bytes: bytes
    manifest_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "dataset_id",
            "pool_sha256",
            "provenance_sha256",
            "source_plan_sha256",
            "inventory_sha256",
            "preview_input_sha256",
            "selection_sha256",
            "partition_sha256",
            "pilot_membership_sha256",
            "holdout_membership_sha256",
            "manifest_sha256",
        ):
            _require_hex64(getattr(self, name), "manifest_hash_invalid")
        if self.observation_count < 0 or self.corpus_count < 0:
            raise ManifestError("manifest_count_invalid")
        if self.pilot_count < 0 or self.holdout_count < 0:
            raise ManifestError("manifest_count_invalid")
        if self.corpus_count != self.pilot_count + self.holdout_count:
            raise ManifestError("manifest_cardinality_mismatch")
        if not isinstance(self.canonical_bytes, bytes):
            raise ManifestError("manifest_bytes_invalid")


@dataclass(frozen=True, slots=True)
class DatasetManifest:
    """Full dataset manifest binding pilot/holdout checksums and blind order."""

    dataset_id: str
    sealed_pool_manifest_sha256: str
    private_manifest_sha256: str
    operator_manifest_sha256: str
    pilot_manifest_sha256: str
    holdout_manifest_sha256: str
    canonical_bytes: bytes
    manifest_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "dataset_id",
            "sealed_pool_manifest_sha256",
            "private_manifest_sha256",
            "operator_manifest_sha256",
            "pilot_manifest_sha256",
            "holdout_manifest_sha256",
            "manifest_sha256",
        ):
            _require_hex64(getattr(self, name), "manifest_hash_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise ManifestError("manifest_bytes_invalid")


def build_sealed_pool_manifest(
    *,
    dataset_id: str,
    pool_sha256: str,
    provenance_sha256: str,
    source_plan_sha256: str,
    inventory_sha256: str,
    preview_input_sha256: str,
    selection_sha256: str,
    partition_sha256: str,
    pilot_membership_sha256: str,
    holdout_membership_sha256: str,
    observation_count: int,
    corpus_count: int,
    pilot_count: int,
    holdout_count: int,
) -> SealedPoolManifest:
    _require_hex64(dataset_id, "manifest_hash_invalid")
    _require_hex64(pool_sha256, "manifest_hash_invalid")
    _require_hex64(provenance_sha256, "manifest_hash_invalid")
    _require_hex64(source_plan_sha256, "manifest_hash_invalid")
    _require_hex64(inventory_sha256, "manifest_hash_invalid")
    _require_hex64(preview_input_sha256, "manifest_hash_invalid")
    _require_hex64(selection_sha256, "manifest_hash_invalid")
    _require_hex64(partition_sha256, "manifest_hash_invalid")
    _require_hex64(pilot_membership_sha256, "manifest_hash_invalid")
    _require_hex64(holdout_membership_sha256, "manifest_hash_invalid")
    if corpus_count != pilot_count + holdout_count:
        raise ManifestError("manifest_cardinality_mismatch")
    payload: dict[str, Any] = {
        "corpus_count": corpus_count,
        "dataset_id": dataset_id,
        "domain": DOMAIN_SEALED_POOL_MANIFEST,
        "holdout_count": holdout_count,
        "holdout_membership_sha256": holdout_membership_sha256,
        "inventory_sha256": inventory_sha256,
        "observation_count": observation_count,
        "partition_sha256": partition_sha256,
        "pilot_count": pilot_count,
        "pilot_membership_sha256": pilot_membership_sha256,
        "pool_sha256": pool_sha256,
        "preview_input_sha256": preview_input_sha256,
        "provenance_sha256": provenance_sha256,
        "schema_version": SCHEMA_SEALED_POOL_MANIFEST,
        "selection_sha256": selection_sha256,
        "source_plan_sha256": source_plan_sha256,
    }
    canonical = _canonical_bytes(payload)
    digest = _domain_hash_bytes(DOMAIN_SEALED_POOL_MANIFEST, canonical)
    return SealedPoolManifest(
        dataset_id=dataset_id,
        pool_sha256=pool_sha256,
        provenance_sha256=provenance_sha256,
        source_plan_sha256=source_plan_sha256,
        inventory_sha256=inventory_sha256,
        preview_input_sha256=preview_input_sha256,
        selection_sha256=selection_sha256,
        partition_sha256=partition_sha256,
        pilot_membership_sha256=pilot_membership_sha256,
        holdout_membership_sha256=holdout_membership_sha256,
        observation_count=observation_count,
        corpus_count=corpus_count,
        pilot_count=pilot_count,
        holdout_count=holdout_count,
        canonical_bytes=canonical,
        manifest_sha256=digest,
    )


def build_checksums_payload(
    *,
    dataset_id: str,
    sealed_pool_manifest_sha256: str,
    private_payloads_sha256: str,
    operator_payloads_sha256: str,
    pilot_payloads_sha256: str,
    holdout_payloads_sha256: str,
) -> tuple[bytes, str]:
    _require_hex64(dataset_id, "manifest_hash_invalid")
    for val in (
        sealed_pool_manifest_sha256,
        private_payloads_sha256,
        operator_payloads_sha256,
        pilot_payloads_sha256,
        holdout_payloads_sha256,
    ):
        _require_hex64(val, "manifest_hash_invalid")
    payload: dict[str, Any] = {
        "dataset_id": dataset_id,
        "domain": DOMAIN_CHECKSUM,
        "holdout_payloads_sha256": holdout_payloads_sha256,
        "operator_payloads_sha256": operator_payloads_sha256,
        "pilot_payloads_sha256": pilot_payloads_sha256,
        "private_payloads_sha256": private_payloads_sha256,
        "sealed_pool_manifest_sha256": sealed_pool_manifest_sha256,
    }
    canonical = _canonical_bytes(payload)
    digest = _domain_hash_bytes(DOMAIN_CHECKSUM, canonical)
    return canonical, digest


def build_dataset_manifest(
    *,
    dataset_id: str,
    sealed_pool_manifest: SealedPoolManifest,
    private_payloads_sha256: str,
    operator_payloads_sha256: str,
    pilot_payloads_sha256: str,
    holdout_payloads_sha256: str,
) -> DatasetManifest:
    _require_hex64(dataset_id, "manifest_hash_invalid")
    for val in (
        private_payloads_sha256,
        operator_payloads_sha256,
        pilot_payloads_sha256,
        holdout_payloads_sha256,
    ):
        _require_hex64(val, "manifest_hash_invalid")
    if sealed_pool_manifest.dataset_id != dataset_id:
        raise ManifestError("manifest_dataset_mismatch")
    payload: dict[str, Any] = {
        "dataset_id": dataset_id,
        "domain": DOMAIN_DATASET_MANIFEST,
        "holdout_payloads_sha256": holdout_payloads_sha256,
        "operator_payloads_sha256": operator_payloads_sha256,
        "pilot_payloads_sha256": pilot_payloads_sha256,
        "private_payloads_sha256": private_payloads_sha256,
        "schema_version": SCHEMA_DATASET_MANIFEST,
        "sealed_pool_manifest_sha256": sealed_pool_manifest.manifest_sha256,
    }
    canonical = _canonical_bytes(payload)
    digest = _domain_hash_bytes(DOMAIN_DATASET_MANIFEST, canonical)
    return DatasetManifest(
        dataset_id=dataset_id,
        sealed_pool_manifest_sha256=sealed_pool_manifest.manifest_sha256,
        private_manifest_sha256=private_payloads_sha256,
        operator_manifest_sha256=operator_payloads_sha256,
        pilot_manifest_sha256=pilot_payloads_sha256,
        holdout_manifest_sha256=holdout_payloads_sha256,
        canonical_bytes=canonical,
        manifest_sha256=digest,
    )


def compute_payloads_sha256(
    payloads: tuple[object, ...],
) -> str:
    """SHA-256 of concatenated canonical payload bytes for a group."""
    # Accept tuple of CanonicalPayload; hash their canonical_bytes concatenated
    # in logical_name sorted order.
    items: list[tuple[str, bytes]] = []
    for p in payloads:
        name = getattr(p, "logical_name", None)
        data = getattr(p, "canonical_bytes", None)
        if not isinstance(name, str) or not isinstance(data, bytes):
            raise ManifestError("manifest_payload_invalid")
        items.append((name, data))
    items.sort(key=lambda x: x[0])
    concatenated = b"".join(b for _, b in items)
    return sha256_bytes(concatenated)


def compute_pool_sha256(pool_lines: tuple[bytes, ...]) -> str:
    joined = b"".join(pool_lines)
    return sha256_bytes(joined)


def blind_order_keys_for_split(
    *,
    dataset_id: str,
    item_semantic_sha256_list: tuple[str, ...],
    split: str,
) -> dict[str, str]:
    if split not in ("pilot", "holdout"):
        raise ManifestError("manifest_split_invalid")
    _require_hex64(dataset_id, "manifest_hash_invalid")
    keys: dict[str, str] = {}
    for sem in item_semantic_sha256_list:
        _require_hex64(sem, "manifest_hash_invalid")
        # split-specific blind order under F10.1E blind-order domain
        keys[sem] = _blind_order_key(DOMAIN_BLIND_ORDER, dataset_id, sem, split)
    # Verify pilot vs holdout keys are distinct for same semantic (domain includes split)
    return keys


def verify_blind_order_disjoint(
    *,
    dataset_id: str,
    pilot_sems: tuple[str, ...],
    holdout_sems: tuple[str, ...],
) -> None:
    pilot_keys = blind_order_keys_for_split(
        dataset_id=dataset_id, item_semantic_sha256_list=pilot_sems, split="pilot"
    )
    holdout_keys = blind_order_keys_for_split(
        dataset_id=dataset_id, item_semantic_sha256_list=holdout_sems, split="holdout"
    )
    overlap = set(pilot_sems) & set(holdout_sems)
    if overlap:
        raise ManifestError("manifest_membership_overlap")
    # Also ensure blind keys for same semantic across splits are never equal (split in preimage)
    for sem in pilot_sems:
        if sem in holdout_keys and pilot_keys[sem] == holdout_keys[sem]:
            raise ManifestError("manifest_blind_order_collision")


def dataset_id_from_materialization(
    *,
    acquisition_sha256: str,
    approval_binding_sha256: str,
    corpus_count: int,
    discovery_policy_sha256: str,
    exclusion_sha256: str,
    holdout_count: int,
    holdout_membership_sha256: str,
    materialization_context_sha256: str,
    partition_policy_sha256: str,
    partition_sha256: str,
    pilot_count: int,
    pilot_membership_sha256: str,
    policy_sha256: str,
    preview_input_sha256: str,
    profile_binding_sha256: str,
    profile_content_sha256: str,
    sampling_policy_sha256: str,
    selection_sha256: str,
    source_plan_sha256: str,
    total_count: int,
) -> str:
    """Re-derive dataset ID via F10.1E domain to prove equality."""
    preimage: dict[str, Any] = {
        "acquisition_sha256": acquisition_sha256,
        "approval_binding_sha256": approval_binding_sha256,
        "corpus_count": corpus_count,
        "discovery_policy_sha256": discovery_policy_sha256,
        "exclusion_sha256": exclusion_sha256,
        "holdout_count": holdout_count,
        "holdout_membership_sha256": holdout_membership_sha256,
        "materialization_context_sha256": materialization_context_sha256,
        "partition_policy_sha256": partition_policy_sha256,
        "partition_sha256": partition_sha256,
        "pilot_count": pilot_count,
        "pilot_membership_sha256": pilot_membership_sha256,
        "policy_sha256": policy_sha256,
        "preview_input_sha256": preview_input_sha256,
        "profile_binding_sha256": profile_binding_sha256,
        "profile_content_sha256": profile_content_sha256,
        "sampling_policy_sha256": sampling_policy_sha256,
        "selection_sha256": selection_sha256,
        "source_plan_sha256": source_plan_sha256,
        "total_count": total_count,
        "materialization_domain": "role-radar:f10.1e-profile-relevance:materialization:v1",
        "materialization_protocol": "f10.1e-profile-relevance-materialization-v1",
        "partition_protocol": "f10.1e-source-stratum-partition-v1",
        "selection_protocol": "f10.1e-source-stratum-selection-v1",
        "gate_protocol": "f10.1e-high-recall-gate-v1",
        "schema_version": "f10.1e-profile-relevance-materialization-context-v1",
    }
    for key in (
        "acquisition_sha256",
        "approval_binding_sha256",
        "discovery_policy_sha256",
        "exclusion_sha256",
        "holdout_membership_sha256",
        "materialization_context_sha256",
        "partition_policy_sha256",
        "partition_sha256",
        "pilot_membership_sha256",
        "policy_sha256",
        "preview_input_sha256",
        "profile_binding_sha256",
        "profile_content_sha256",
        "sampling_policy_sha256",
        "selection_sha256",
        "source_plan_sha256",
    ):
        _require_hex64(str(preimage[key]), "manifest_hash_invalid")
    return _domain_hash(DOMAIN_DATASET_ID, canonical_json_bytes(preimage))


def verify_manifest_chain(
    *,
    sealed_pool_manifest: SealedPoolManifest,
    dataset_manifest: DatasetManifest,
) -> None:
    if sealed_pool_manifest.manifest_sha256 != dataset_manifest.sealed_pool_manifest_sha256:
        raise ManifestError("manifest_chain_mismatch")
    if sealed_pool_manifest.dataset_id != dataset_manifest.dataset_id:
        raise ManifestError("manifest_dataset_mismatch")
    # Recompute hashes to prove canonicity
    expected_sealed = _domain_hash_bytes(
        DOMAIN_SEALED_POOL_MANIFEST, sealed_pool_manifest.canonical_bytes
    )
    if expected_sealed != sealed_pool_manifest.manifest_sha256:
        raise ManifestError("manifest_hash_mismatch")
    expected_dataset = _domain_hash_bytes(DOMAIN_DATASET_MANIFEST, dataset_manifest.canonical_bytes)
    if expected_dataset != dataset_manifest.manifest_sha256:
        raise ManifestError("manifest_hash_mismatch")


__all__ = [
    "DOMAIN_CHECKSUM",
    "DOMAIN_DATASET_MANIFEST",
    "DOMAIN_SEALED_POOL_MANIFEST",
    "SCHEMA_DATASET_MANIFEST",
    "SCHEMA_SEALED_POOL_MANIFEST",
    "DatasetManifest",
    "ManifestError",
    "SealedPoolManifest",
    "blind_order_keys_for_split",
    "build_checksums_payload",
    "build_dataset_manifest",
    "build_sealed_pool_manifest",
    "compute_payloads_sha256",
    "compute_pool_sha256",
    "dataset_id_from_materialization",
    "verify_blind_order_disjoint",
    "verify_manifest_chain",
]
