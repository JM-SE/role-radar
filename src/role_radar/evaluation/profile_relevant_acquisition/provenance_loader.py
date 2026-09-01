"""Strict, side-effect-free loader for an offline provenance artifact."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final

from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ProvenanceArtifact,
    SeedInputs,
)

MAX_PROVENANCE_BYTES: Final[int] = 128 * 1024
PROVENANCE_DOMAIN: Final[str] = "role-radar:f10.1f:provenance:v1"
PROVENANCE_SCHEMA: Final[str] = "f10.1f-provenance-v1"
PROVENANCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifact_class",
        "commit_sha256",
        "lineage_id",
        "namespace_sha256",
        "operation_id",
        "policy_sha256",
        "provenance_sha256",
        "schema_version",
        "seed_inputs",
        "window_sha256",
    }
)


class ProvenanceLoadError(ValueError):
    """Stable detail-free provenance parsing/verification failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def provenance_hash(canonical_bytes: bytes) -> str:
    if not isinstance(canonical_bytes, bytes):
        raise ProvenanceLoadError("provenance_bytes_invalid")
    digest = hashlib.sha256()
    digest.update(PROVENANCE_DOMAIN.encode("ascii"))
    digest.update(b"\x00")
    digest.update(canonical_bytes)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProvenanceLoadError("provenance_canonical_invalid") from exc


def _object(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_PROVENANCE_BYTES:
        raise ProvenanceLoadError("provenance_bounds_exceeded")
    if not raw.endswith(b"\n") or raw[:-1].count(b"\n") != 0:
        raise ProvenanceLoadError("provenance_record_invalid")
    try:
        value = json.loads(raw[:-1].decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ProvenanceLoadError("provenance_json_invalid") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ProvenanceLoadError("provenance_object_invalid")
    if set(value) != PROVENANCE_KEYS:
        raise ProvenanceLoadError("provenance_fields_invalid")
    if _canonical(value) != raw[:-1]:
        raise ProvenanceLoadError("provenance_noncanonical")
    return value


def load_provenance_bytes(raw: bytes) -> ProvenanceArtifact:
    value = _object(raw)
    if value["schema_version"] != PROVENANCE_SCHEMA:
        raise ProvenanceLoadError("provenance_schema_invalid")
    seed_data = value["seed_inputs"]
    if not isinstance(seed_data, dict) or set(seed_data) != {"selection_seed", "partition_seed"}:
        raise ProvenanceLoadError("provenance_seed_inputs_invalid")
    try:
        seeds = SeedInputs(seed_data["selection_seed"], seed_data["partition_seed"])
    except (TypeError, ValueError) as exc:
        raise ProvenanceLoadError("provenance_seed_inputs_invalid") from exc
    try:
        artifact_class = ArtifactClass(value["artifact_class"])
    except (TypeError, ValueError) as exc:
        raise ProvenanceLoadError("provenance_artifact_class_invalid") from exc
    for field in (
        "commit_sha256",
        "window_sha256",
        "namespace_sha256",
        "policy_sha256",
    ):
        candidate = value[field]
        if (
            not isinstance(candidate, str)
            or len(candidate) != 64
            or any(char not in "0123456789abcdef" for char in candidate)
        ):
            raise ProvenanceLoadError(f"provenance_{field.removesuffix('_sha256')}_invalid")
    operation_id = value["operation_id"]
    lineage_id = value["lineage_id"]
    if not isinstance(operation_id, str) or not operation_id.strip():
        raise ProvenanceLoadError("provenance_operation_invalid")
    if not isinstance(lineage_id, str) or not lineage_id.strip():
        raise ProvenanceLoadError("provenance_lineage_invalid")
    supplied_digest = value["provenance_sha256"]
    if (
        not isinstance(supplied_digest, str)
        or len(supplied_digest) != 64
        or any(char not in "0123456789abcdef" for char in supplied_digest)
    ):
        raise ProvenanceLoadError("provenance_hash_invalid")
    unsigned = dict(value)
    del unsigned["provenance_sha256"]
    if supplied_digest != provenance_hash(_canonical(unsigned)):
        raise ProvenanceLoadError("provenance_hash_mismatch")
    try:
        return ProvenanceArtifact(
            schema_version=PROVENANCE_SCHEMA,
            operation_id=operation_id,
            lineage_id=lineage_id,
            commit_sha256=value["commit_sha256"],
            window_sha256=value["window_sha256"],
            namespace_sha256=value["namespace_sha256"],
            policy_sha256=value["policy_sha256"],
            artifact_class=artifact_class,
            seed_inputs=seeds,
            provenance_sha256=supplied_digest,
            canonical_bytes=raw,
        )
    except (TypeError, ValueError) as exc:
        raise ProvenanceLoadError("provenance_contract_invalid") from exc


def build_provenance_bytes(
    *,
    operation_id: str,
    lineage_id: str,
    commit_sha256: str,
    window_sha256: str,
    namespace_sha256: str,
    policy_sha256: str,
    artifact_class: ArtifactClass,
    selection_seed: str,
    partition_seed: str,
) -> bytes:
    """Build explicit synthetic/test bytes without supplying defaults."""

    value = {
        "artifact_class": artifact_class.value,
        "commit_sha256": commit_sha256,
        "lineage_id": lineage_id,
        "namespace_sha256": namespace_sha256,
        "operation_id": operation_id,
        "policy_sha256": policy_sha256,
        "schema_version": PROVENANCE_SCHEMA,
        "seed_inputs": {
            "partition_seed": partition_seed,
            "selection_seed": selection_seed,
        },
        "window_sha256": window_sha256,
    }
    value["provenance_sha256"] = provenance_hash(_canonical(value))
    raw = _canonical(value) + b"\n"
    load_provenance_bytes(raw)
    return raw


def load_provenance(value: Mapping[str, object]) -> ProvenanceArtifact:
    if not isinstance(value, Mapping):
        raise ProvenanceLoadError("provenance_object_invalid")
    return load_provenance_bytes(_canonical(dict(value)) + b"\n")


__all__ = [
    "PROVENANCE_DOMAIN",
    "PROVENANCE_SCHEMA",
    "ProvenanceLoadError",
    "build_provenance_bytes",
    "load_provenance",
    "load_provenance_bytes",
    "provenance_hash",
]
