"""F10.1F freeze — the single immutable publish/verify/capability-seal transaction.

Consumes the exact F10.1E payload bytes returned by the Gate F materializer
(``gate_f.run_gate_f_materialization``) and performs exactly one fenced
transaction under the new private root:

1. Revalidate provenance and the exact expected bindings (stale-safety).
2. Strictly parse the operator/pilot-binding/holdout-binding/population
   payload records and cross-check every binding against those bytes.
3. Publish corpus (private + operator), pilot, and sealed-holdout artifacts
   no-replace together with both manifests and the checksum payload.
4. Verify every published byte by bounded no-follow read-back, recompute all
   group checksums from disk, and validate the manifest chain.
5. Seal the private/pilot/sealed-holdout capabilities and verify them.
6. Emit the immutable freeze receipt and re-read it.

There is no second publication path: this module is the only writer of frozen
benchmark artifacts, it composes the shared filesystem primitive owner plus the
manifest/checksum and capability adapters, and it never imports the Gate E
module or any materialization function. Rollback never deletes published
bytes; a failed transaction leaves immutable evidence and an identical rerun
completes idempotently via no-replace writes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from role_radar.evaluation.fresh_acquisition.capability import (
    KIND_PILOT,
    KIND_PRIVATE,
    KIND_SEALED_HOLDOUT,
    CapabilityError,
    build_capability_seal,
    verify_capability_seal,
    verify_capability_set,
    write_capability_seal,
)
from role_radar.evaluation.fresh_acquisition.filesystem import (
    FilesystemError,
    bounded_read,
    canonical_json_bytes,
    ensure_private_root,
    fenced_lock,
    resolve_nofollow,
    write_no_replace,
)
from role_radar.evaluation.fresh_acquisition.manifest import (
    DatasetManifest,
    ManifestError,
    SealedPoolManifest,
    build_checksums_payload,
    build_dataset_manifest,
    build_sealed_pool_manifest,
    compute_payloads_sha256,
    verify_manifest_chain,
)
from role_radar.evaluation.fresh_acquisition.provenance import (
    LIVE_NAMESPACE,
    LIVE_ROOT,
    ProvenanceBundle,
    ProvenanceError,
    validate_provenance,
)
from role_radar.evaluation.profile_relevance.contracts import (
    CanonicalPayload,
    MaterializedPayloads,
)

SCHEMA_FREEZE_RECEIPT: Final[str] = "f10.1f-freeze-receipt-v1"
DOMAIN_FREEZE_RECEIPT: Final[str] = "role-radar:f10.1f:freeze-receipt:v1"
DOMAIN_CORPUS_ID: Final[str] = "role-radar:f10.1f:corpus-id:v1"
DOMAIN_PILOT_ID: Final[str] = "role-radar:f10.1f:pilot-id:v1"
DOMAIN_HOLDOUT_ID: Final[str] = "role-radar:f10.1f:holdout-id:v1"

MANIFEST_NAME: Final[str] = "manifest.json"
SEALED_POOL_MANIFEST_NAME: Final[str] = "sealed_pool_manifest.json"
CHECKSUMS_NAME: Final[str] = "checksums.sha256"
RECEIPT_NAME: Final[str] = "receipt.json"

DIRNAME_OPERATOR: Final[str] = "operator"
DIRNAME_PRIVATE: Final[str] = "private"
DIRNAME_PILOT: Final[str] = "pilot"
DIRNAME_SEALED_HOLDOUT: Final[str] = "sealed_holdout"

OPERATOR_LOGICAL_NAME: Final[str] = "operator_preview"
POPULATION_LOGICAL_NAME: Final[str] = "population"
PILOT_BINDING_LOGICAL_NAME: Final[str] = "pilot_binding"
HOLDOUT_BINDING_LOGICAL_NAME: Final[str] = "holdout_binding"

DATASET_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
LOGICAL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_TOTAL_PAYLOAD_BYTES: Final[int] = 64 * 1024 * 1024

# Recursive denylist for sanitized external output — exact keys only.
FORBIDDEN_SUMMARY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "company",
        "description",
        "items",
        "label",
        "membership",
        "observation",
        "probability",
        "query",
        "rank",
        "records",
        "score",
        "source",
        "source_url",
        "stratum",
        "title",
        "url",
    }
)


class FreezeError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise FreezeError(code)
    if any(c not in "0123456789abcdef" for c in value):
        raise FreezeError(code)


def _require_positive_int(value: int, code: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise FreezeError(code)


@dataclass(frozen=True, slots=True)
class FreezeBindings:
    """Exact expected bindings over the approved unchanged design."""

    dataset_id: str
    pool_sha256: str
    provenance_sha256: str
    inventory_sha256: str
    source_plan_sha256: str
    preview_input_sha256: str
    selection_sha256: str
    partition_sha256: str
    pilot_membership_sha256: str
    holdout_membership_sha256: str
    observation_count: int
    corpus_count: int
    pilot_count: int
    holdout_count: int
    namespace: str
    root: str

    def __post_init__(self) -> None:
        for name in (
            "dataset_id",
            "pool_sha256",
            "provenance_sha256",
            "inventory_sha256",
            "source_plan_sha256",
            "preview_input_sha256",
            "selection_sha256",
            "partition_sha256",
            "pilot_membership_sha256",
            "holdout_membership_sha256",
        ):
            _require_hex64(getattr(self, name), "freeze_binding_hash_invalid")
        for name in ("observation_count", "corpus_count", "pilot_count", "holdout_count"):
            _require_positive_int(getattr(self, name), "freeze_binding_count_invalid")
        if self.corpus_count != self.pilot_count + self.holdout_count:
            raise FreezeError("freeze_cardinality_mismatch")
        if not isinstance(self.namespace, str) or self.namespace != LIVE_NAMESPACE:
            raise FreezeError("freeze_namespace_mismatch")
        if not isinstance(self.root, str) or not self.root.startswith("/"):
            raise FreezeError("freeze_root_invalid")


@dataclass(frozen=True, slots=True)
class FreezeReceipt:
    dataset_id: str
    namespace: str
    corpus_id: str
    pilot_id: str
    holdout_id: str
    sealed_pool_manifest_sha256: str
    dataset_manifest_sha256: str
    private_payloads_sha256: str
    operator_payloads_sha256: str
    pilot_payloads_sha256: str
    holdout_payloads_sha256: str
    private_artifact_count: int
    pilot_artifact_count: int
    holdout_artifact_count: int
    capability_kinds: tuple[str, ...]
    transaction_complete: bool
    canonical_bytes: bytes
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class FrozenBenchmark:
    dataset_id: str
    namespace: str
    root: str
    corpus_id: str
    pilot_id: str
    holdout_id: str
    sealed_pool_manifest: SealedPoolManifest
    dataset_manifest: DatasetManifest
    receipt: FreezeReceipt
    corpus_path: str
    pilot_path: str
    sealed_holdout_path: str
    capability_kinds: tuple[str, ...]
    verified: bool


def _domain_hash(domain: str, canonical: bytes) -> str:
    if not domain.isascii():
        raise FreezeError("freeze_domain_invalid")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


def _payload_object(raw: bytes, code: str) -> dict[str, Any]:
    """Strict single-record JSON payload: one trailing LF, canonical form."""
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise FreezeError(code)
    body = raw[:-1]
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise FreezeError(code) from exc
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise FreezeError(code)
    try:
        rebuilt = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise FreezeError(code) from exc
    if rebuilt != body:
        raise FreezeError("freeze_payload_noncanonical")
    return value


def _obj_str(obj: Mapping[str, Any], key: str, code: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise FreezeError(code)
    return value


def _obj_int(obj: Mapping[str, Any], key: str, code: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise FreezeError(code)
    return value


def _single_payload(group: tuple[CanonicalPayload, ...], logical_name: str) -> CanonicalPayload:
    matches = [p for p in group if p.logical_name == logical_name]
    if len(matches) != 1:
        raise FreezeError("freeze_payload_record_missing")
    return matches[0]


def _validate_payload_groups(payloads: MaterializedPayloads) -> None:
    groups = (
        payloads.private_payloads,
        payloads.operator_payloads,
        payloads.pilot_payloads,
        payloads.holdout_payloads,
    )
    seen: set[str] = set()
    total = 0
    for group in groups:
        if not group:
            raise FreezeError("freeze_group_empty")
        for payload in group:
            if LOGICAL_NAME_RE.fullmatch(payload.logical_name) is None:
                raise FreezeError("freeze_logical_name_invalid")
            if payload.logical_name in seen:
                raise FreezeError("freeze_logical_name_duplicate")
            seen.add(payload.logical_name)
            if not isinstance(payload.canonical_bytes, bytes) or not payload.canonical_bytes:
                raise FreezeError("freeze_payload_bytes_invalid")
            total += len(payload.canonical_bytes)
    if total > MAX_TOTAL_PAYLOAD_BYTES:
        raise FreezeError("freeze_total_size_exceeded")


def _cross_check_payload_records(bindings: FreezeBindings, payloads: MaterializedPayloads) -> None:
    """Bind every derivable record field to the exact expected bindings."""
    operator = _payload_object(
        _single_payload(payloads.operator_payloads, OPERATOR_LOGICAL_NAME).canonical_bytes,
        "freeze_operator_record_invalid",
    )
    population = _payload_object(
        _single_payload(payloads.private_payloads, POPULATION_LOGICAL_NAME).canonical_bytes,
        "freeze_population_record_invalid",
    )
    pilot_binding = _payload_object(
        _single_payload(payloads.pilot_payloads, PILOT_BINDING_LOGICAL_NAME).canonical_bytes,
        "freeze_pilot_binding_record_invalid",
    )
    holdout_binding = _payload_object(
        _single_payload(payloads.holdout_payloads, HOLDOUT_BINDING_LOGICAL_NAME).canonical_bytes,
        "freeze_holdout_binding_record_invalid",
    )

    if _obj_str(operator, "dataset_id", "freeze_operator_record_invalid") != bindings.dataset_id:
        raise FreezeError("freeze_dataset_mismatch")
    if (
        _obj_str(operator, "preview_input_sha256", "freeze_operator_record_invalid")
        != bindings.preview_input_sha256
    ):
        raise FreezeError("freeze_preview_input_mismatch")
    if (
        _obj_str(operator, "selection_sha256", "freeze_operator_record_invalid")
        != bindings.selection_sha256
    ):
        raise FreezeError("freeze_selection_mismatch")
    if (
        _obj_int(operator, "corpus_count", "freeze_operator_record_invalid")
        != bindings.corpus_count
    ):
        raise FreezeError("freeze_corpus_count_mismatch")
    if _obj_int(operator, "pilot_count", "freeze_operator_record_invalid") != bindings.pilot_count:
        raise FreezeError("freeze_pilot_count_mismatch")
    if (
        _obj_int(operator, "holdout_count", "freeze_operator_record_invalid")
        != bindings.holdout_count
    ):
        raise FreezeError("freeze_holdout_count_mismatch")

    if (
        _obj_str(population, "preview_input_sha256", "freeze_population_record_invalid")
        != bindings.preview_input_sha256
    ):
        raise FreezeError("freeze_preview_input_mismatch")
    if (
        _obj_int(population, "observation_count", "freeze_population_record_invalid")
        != bindings.observation_count
    ):
        raise FreezeError("freeze_observation_count_mismatch")

    if _obj_str(pilot_binding, "split", "freeze_pilot_binding_record_invalid") != "pilot":
        raise FreezeError("freeze_pilot_split_invalid")
    if (
        _obj_str(pilot_binding, "dataset_id", "freeze_pilot_binding_record_invalid")
        != bindings.dataset_id
    ):
        raise FreezeError("freeze_dataset_mismatch")
    if _obj_int(pilot_binding, "count", "freeze_pilot_binding_record_invalid") != (
        bindings.pilot_count
    ):
        raise FreezeError("freeze_pilot_count_mismatch")
    if (
        _obj_str(pilot_binding, "pilot_membership_sha256", "freeze_pilot_binding_record_invalid")
        != bindings.pilot_membership_sha256
    ):
        raise FreezeError("freeze_pilot_membership_mismatch")

    if _obj_str(holdout_binding, "split", "freeze_holdout_binding_record_invalid") != "holdout":
        raise FreezeError("freeze_holdout_split_invalid")
    if (
        _obj_str(holdout_binding, "dataset_id", "freeze_holdout_binding_record_invalid")
        != bindings.dataset_id
    ):
        raise FreezeError("freeze_dataset_mismatch")
    if _obj_int(holdout_binding, "count", "freeze_holdout_binding_record_invalid") != (
        bindings.holdout_count
    ):
        raise FreezeError("freeze_holdout_count_mismatch")
    if (
        _obj_str(
            holdout_binding,
            "holdout_membership_sha256",
            "freeze_holdout_binding_record_invalid",
        )
        != bindings.holdout_membership_sha256
    ):
        raise FreezeError("freeze_holdout_membership_mismatch")


def _group_checksum(group: tuple[CanonicalPayload, ...]) -> str:
    try:
        return compute_payloads_sha256(group)
    except ManifestError as exc:
        raise FreezeError(exc.code) from exc


def _derive_split_ids(
    *,
    dataset_id: str,
    private_payloads_sha256: str,
    operator_payloads_sha256: str,
    pilot_payloads_sha256: str,
    holdout_payloads_sha256: str,
) -> tuple[str, str, str]:
    corpus_preimage: dict[str, Any] = {
        "dataset_id": dataset_id,
        "domain": DOMAIN_CORPUS_ID,
        "operator_payloads_sha256": operator_payloads_sha256,
        "private_payloads_sha256": private_payloads_sha256,
    }
    pilot_preimage: dict[str, Any] = {
        "dataset_id": dataset_id,
        "domain": DOMAIN_PILOT_ID,
        "pilot_payloads_sha256": pilot_payloads_sha256,
    }
    holdout_preimage: dict[str, Any] = {
        "dataset_id": dataset_id,
        "domain": DOMAIN_HOLDOUT_ID,
        "holdout_payloads_sha256": holdout_payloads_sha256,
    }
    corpus_id = _domain_hash(DOMAIN_CORPUS_ID, canonical_json_bytes(corpus_preimage))
    pilot_id = _domain_hash(DOMAIN_PILOT_ID, canonical_json_bytes(pilot_preimage))
    holdout_id = _domain_hash(DOMAIN_HOLDOUT_ID, canonical_json_bytes(holdout_preimage))
    return corpus_id, pilot_id, holdout_id


def _group_files(
    dirname: str, group: tuple[CanonicalPayload, ...]
) -> list[tuple[tuple[str, ...], bytes]]:
    return [
        ((dirname, f"{payload.logical_name}.json"), payload.canonical_bytes)
        for payload in sorted(group, key=lambda p: p.logical_name)
    ]


def _ds_path(root: Path, dataset_id: str, *parts: str) -> Path:
    try:
        return resolve_nofollow(root, dataset_id, *parts)
    except FilesystemError as exc:
        raise FreezeError(exc.code) from exc


def _publish_files(root: Path, dataset_id: str, files: list[tuple[tuple[str, ...], bytes]]) -> None:
    """No-replace publication of every planned file; caller holds the fence."""
    ds_dir = _ds_path(root, dataset_id)
    try:
        if not ds_dir.exists():
            try:
                ds_dir.mkdir(mode=0o700)
            except OSError as exc:
                raise FreezeError("freeze_mkdir_failed") from exc
        touched_dirs: set[Path] = set()
        for parts, data in files:
            path = _ds_path(root, dataset_id, *parts)
            if path.parent not in touched_dirs:
                try:
                    ensure_private_root(path.parent)
                except FilesystemError as exc:
                    raise FreezeError(exc.code) from exc
                touched_dirs.add(path.parent)
            try:
                write_no_replace(path, data)
            except FilesystemError as exc:
                raise FreezeError(exc.code) from exc
            try:
                path.chmod(0o600)
            except OSError as exc:
                raise FreezeError("freeze_chmod_failed") from exc
        for directory in touched_dirs:
            try:
                directory.chmod(0o700)
            except OSError as exc:
                raise FreezeError("freeze_chmod_failed") from exc
        try:
            ds_dir.chmod(0o700)
        except OSError as exc:
            raise FreezeError("freeze_chmod_failed") from exc
    except FilesystemError as exc:
        raise FreezeError(exc.code) from exc


def _read_back(path: Path, expected: bytes) -> None:
    try:
        data = bounded_read(path)
    except FilesystemError as exc:
        raise FreezeError(exc.code) from exc
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        raise FreezeError("freeze_verify_stat_failed") from exc
    if data != expected:
        raise FreezeError("freeze_verify_byte_mismatch")
    if mode != 0o600:
        raise FreezeError("freeze_verify_mode_invalid")


@dataclass(frozen=True, slots=True)
class _DiskPayload:
    logical_name: str
    canonical_bytes: bytes


def _verify_group_from_disk(
    root: Path,
    dataset_id: str,
    dirname: str,
    group: tuple[CanonicalPayload, ...],
    expected_sha256: str,
) -> None:
    disk_items: list[_DiskPayload] = []
    for payload in sorted(group, key=lambda p: p.logical_name):
        path = _ds_path(root, dataset_id, dirname, f"{payload.logical_name}.json")
        _read_back(path, payload.canonical_bytes)
        disk_items.append(
            _DiskPayload(logical_name=payload.logical_name, canonical_bytes=payload.canonical_bytes)
        )
    recomputed = compute_payloads_sha256(tuple(disk_items))
    if recomputed != expected_sha256:
        raise FreezeError("freeze_verify_group_checksum_mismatch")


def _deny_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key in FORBIDDEN_SUMMARY_KEYS:
                raise FreezeError("freeze_summary_key_forbidden")
            _deny_forbidden_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _deny_forbidden_keys(item)


def _build_receipt(
    *,
    bindings: FreezeBindings,
    corpus_id: str,
    pilot_id: str,
    holdout_id: str,
    sealed_pool_manifest: SealedPoolManifest,
    dataset_manifest: DatasetManifest,
    private_payloads_sha256: str,
    operator_payloads_sha256: str,
    pilot_payloads_sha256: str,
    holdout_payloads_sha256: str,
    private_artifact_count: int,
    pilot_artifact_count: int,
    holdout_artifact_count: int,
    capability_kinds: tuple[str, ...],
) -> FreezeReceipt:
    payload: dict[str, Any] = {
        "capability_kinds": sorted(capability_kinds),
        "corpus_id": corpus_id,
        "dataset_id": bindings.dataset_id,
        "dataset_manifest_sha256": dataset_manifest.manifest_sha256,
        "domain": DOMAIN_FREEZE_RECEIPT,
        "holdout_artifact_count": holdout_artifact_count,
        "holdout_id": holdout_id,
        "holdout_payloads_sha256": holdout_payloads_sha256,
        "namespace": bindings.namespace,
        "operator_payloads_sha256": operator_payloads_sha256,
        "pilot_artifact_count": pilot_artifact_count,
        "pilot_id": pilot_id,
        "pilot_payloads_sha256": pilot_payloads_sha256,
        "private_artifact_count": private_artifact_count,
        "private_payloads_sha256": private_payloads_sha256,
        "schema_version": SCHEMA_FREEZE_RECEIPT,
        "sealed_pool_manifest_sha256": sealed_pool_manifest.manifest_sha256,
        "transaction_complete": True,
    }
    _deny_forbidden_keys(payload)
    canonical = canonical_json_bytes(payload)
    digest = _domain_hash(DOMAIN_FREEZE_RECEIPT, canonical)
    return FreezeReceipt(
        dataset_id=bindings.dataset_id,
        namespace=bindings.namespace,
        corpus_id=corpus_id,
        pilot_id=pilot_id,
        holdout_id=holdout_id,
        sealed_pool_manifest_sha256=sealed_pool_manifest.manifest_sha256,
        dataset_manifest_sha256=dataset_manifest.manifest_sha256,
        private_payloads_sha256=private_payloads_sha256,
        operator_payloads_sha256=operator_payloads_sha256,
        pilot_payloads_sha256=pilot_payloads_sha256,
        holdout_payloads_sha256=holdout_payloads_sha256,
        private_artifact_count=private_artifact_count,
        pilot_artifact_count=pilot_artifact_count,
        holdout_artifact_count=holdout_artifact_count,
        capability_kinds=tuple(sorted(capability_kinds)),
        transaction_complete=True,
        canonical_bytes=canonical,
        receipt_sha256=digest,
    )


def run_freeze_transaction(
    *,
    root: Path,
    bindings: FreezeBindings,
    payloads: MaterializedPayloads,
    provenance: ProvenanceBundle,
) -> FrozenBenchmark:
    """Execute the one immutable publish/verify/capability-seal transaction."""
    # -- revalidation of upstream bindings (never originates design values) --
    if not isinstance(provenance, ProvenanceBundle):
        raise FreezeError("freeze_provenance_invalid")
    try:
        validate_provenance(provenance)
    except ProvenanceError as exc:
        raise FreezeError(exc.code) from exc
    if provenance.provenance_sha256 != bindings.provenance_sha256:
        raise FreezeError("freeze_provenance_mismatch")
    if provenance.inventory_sha256 != bindings.inventory_sha256:
        raise FreezeError("freeze_inventory_mismatch")
    if provenance.namespace != bindings.namespace:
        raise FreezeError("freeze_lineage_mismatch")
    if DATASET_ID_RE.fullmatch(bindings.dataset_id) is None:
        raise FreezeError("freeze_dataset_id_invalid")
    # Root binding: exact match required; live deployments additionally pin /opt.
    if str(root) != bindings.root:
        raise FreezeError("freeze_root_mismatch")
    if str(root).startswith("/opt/") and str(root) != LIVE_ROOT:
        raise FreezeError("freeze_root_mismatch")
    try:
        ensure_private_root(root)
    except FilesystemError as exc:
        raise FreezeError(exc.code) from exc
    if not isinstance(payloads, MaterializedPayloads):
        raise FreezeError("freeze_payloads_invalid")
    _validate_payload_groups(payloads)
    _cross_check_payload_records(bindings, payloads)

    # -- checksums over the exact F10.1E payload bytes --
    private_payloads_sha256 = _group_checksum(payloads.private_payloads)
    operator_payloads_sha256 = _group_checksum(payloads.operator_payloads)
    pilot_payloads_sha256 = _group_checksum(payloads.pilot_payloads)
    holdout_payloads_sha256 = _group_checksum(payloads.holdout_payloads)

    # -- manifests (F10.1F-owned) --
    try:
        sealed_pool_manifest = build_sealed_pool_manifest(
            dataset_id=bindings.dataset_id,
            pool_sha256=bindings.pool_sha256,
            provenance_sha256=bindings.provenance_sha256,
            source_plan_sha256=bindings.source_plan_sha256,
            inventory_sha256=bindings.inventory_sha256,
            preview_input_sha256=bindings.preview_input_sha256,
            selection_sha256=bindings.selection_sha256,
            partition_sha256=bindings.partition_sha256,
            pilot_membership_sha256=bindings.pilot_membership_sha256,
            holdout_membership_sha256=bindings.holdout_membership_sha256,
            observation_count=bindings.observation_count,
            corpus_count=bindings.corpus_count,
            pilot_count=bindings.pilot_count,
            holdout_count=bindings.holdout_count,
        )
        dataset_manifest = build_dataset_manifest(
            dataset_id=bindings.dataset_id,
            sealed_pool_manifest=sealed_pool_manifest,
            private_payloads_sha256=private_payloads_sha256,
            operator_payloads_sha256=operator_payloads_sha256,
            pilot_payloads_sha256=pilot_payloads_sha256,
            holdout_payloads_sha256=holdout_payloads_sha256,
        )
        checksums_canonical, _ = build_checksums_payload(
            dataset_id=bindings.dataset_id,
            sealed_pool_manifest_sha256=sealed_pool_manifest.manifest_sha256,
            private_payloads_sha256=private_payloads_sha256,
            operator_payloads_sha256=operator_payloads_sha256,
            pilot_payloads_sha256=pilot_payloads_sha256,
            holdout_payloads_sha256=holdout_payloads_sha256,
        )
    except ManifestError as exc:
        raise FreezeError(exc.code) from exc

    corpus_id, pilot_id, holdout_id = _derive_split_ids(
        dataset_id=bindings.dataset_id,
        private_payloads_sha256=private_payloads_sha256,
        operator_payloads_sha256=operator_payloads_sha256,
        pilot_payloads_sha256=pilot_payloads_sha256,
        holdout_payloads_sha256=holdout_payloads_sha256,
    )

    files: list[tuple[tuple[str, ...], bytes]] = [
        ((MANIFEST_NAME,), dataset_manifest.canonical_bytes),
        ((SEALED_POOL_MANIFEST_NAME,), sealed_pool_manifest.canonical_bytes),
        ((CHECKSUMS_NAME,), checksums_canonical),
        *_group_files(DIRNAME_OPERATOR, payloads.operator_payloads),
        *_group_files(DIRNAME_PRIVATE, payloads.private_payloads),
        *_group_files(DIRNAME_PILOT, payloads.pilot_payloads),
        *_group_files(DIRNAME_SEALED_HOLDOUT, payloads.holdout_payloads),
    ]

    seals = {
        KIND_PRIVATE: build_capability_seal(
            dataset_id=bindings.dataset_id,
            namespace=bindings.namespace,
            root=str(root),
            kind=KIND_PRIVATE,
            payloads_sha256=private_payloads_sha256,
            artifact_count=len(payloads.private_payloads),
        ),
        KIND_PILOT: build_capability_seal(
            dataset_id=bindings.dataset_id,
            namespace=bindings.namespace,
            root=str(root),
            kind=KIND_PILOT,
            payloads_sha256=pilot_payloads_sha256,
            artifact_count=len(payloads.pilot_payloads),
        ),
        KIND_SEALED_HOLDOUT: build_capability_seal(
            dataset_id=bindings.dataset_id,
            namespace=bindings.namespace,
            root=str(root),
            kind=KIND_SEALED_HOLDOUT,
            payloads_sha256=holdout_payloads_sha256,
            artifact_count=len(payloads.holdout_payloads),
        ),
    }

    # -- the one transaction: publish -> verify -> capability seal -> receipt --
    try:
        with fenced_lock(root):
            _publish_files(root, bindings.dataset_id, files)
            for parts, data in files:
                _read_back(_ds_path(root, bindings.dataset_id, *parts), data)
            try:
                verify_manifest_chain(
                    sealed_pool_manifest=sealed_pool_manifest,
                    dataset_manifest=dataset_manifest,
                )
            except ManifestError as exc:
                raise FreezeError(exc.code) from exc
            _verify_group_from_disk(
                root,
                bindings.dataset_id,
                DIRNAME_PRIVATE,
                payloads.private_payloads,
                private_payloads_sha256,
            )
            _verify_group_from_disk(
                root,
                bindings.dataset_id,
                DIRNAME_OPERATOR,
                payloads.operator_payloads,
                operator_payloads_sha256,
            )
            _verify_group_from_disk(
                root,
                bindings.dataset_id,
                DIRNAME_PILOT,
                payloads.pilot_payloads,
                pilot_payloads_sha256,
            )
            _verify_group_from_disk(
                root,
                bindings.dataset_id,
                DIRNAME_SEALED_HOLDOUT,
                payloads.holdout_payloads,
                holdout_payloads_sha256,
            )
            for kind, seal in seals.items():
                try:
                    write_capability_seal(seal)
                    verify_capability_seal(
                        root=root,
                        dataset_id=bindings.dataset_id,
                        kind=kind,
                        expected_payloads_sha256=seal.payloads_sha256,
                        expected_artifact_count=seal.artifact_count,
                        expected_namespace=bindings.namespace,
                    )
                except CapabilityError as exc:
                    raise FreezeError(exc.code) from exc
            receipt = _build_receipt(
                bindings=bindings,
                corpus_id=corpus_id,
                pilot_id=pilot_id,
                holdout_id=holdout_id,
                sealed_pool_manifest=sealed_pool_manifest,
                dataset_manifest=dataset_manifest,
                private_payloads_sha256=private_payloads_sha256,
                operator_payloads_sha256=operator_payloads_sha256,
                pilot_payloads_sha256=pilot_payloads_sha256,
                holdout_payloads_sha256=holdout_payloads_sha256,
                private_artifact_count=len(payloads.private_payloads),
                pilot_artifact_count=len(payloads.pilot_payloads),
                holdout_artifact_count=len(payloads.holdout_payloads),
                capability_kinds=tuple(seals.keys()),
            )
            receipt_path = _ds_path(root, bindings.dataset_id, RECEIPT_NAME)
            try:
                write_no_replace(receipt_path, receipt.canonical_bytes)
            except FilesystemError as exc:
                raise FreezeError(exc.code) from exc
            try:
                receipt_path.chmod(0o600)
            except OSError as exc:
                raise FreezeError("freeze_chmod_failed") from exc
            _read_back(receipt_path, receipt.canonical_bytes)
    except FilesystemError as exc:
        raise FreezeError(exc.code) from exc

    return FrozenBenchmark(
        dataset_id=bindings.dataset_id,
        namespace=bindings.namespace,
        root=str(root),
        corpus_id=corpus_id,
        pilot_id=pilot_id,
        holdout_id=holdout_id,
        sealed_pool_manifest=sealed_pool_manifest,
        dataset_manifest=dataset_manifest,
        receipt=receipt,
        corpus_path=str(_ds_path(root, bindings.dataset_id, DIRNAME_PRIVATE)),
        pilot_path=str(_ds_path(root, bindings.dataset_id, DIRNAME_PILOT)),
        sealed_holdout_path=str(_ds_path(root, bindings.dataset_id, DIRNAME_SEALED_HOLDOUT)),
        capability_kinds=receipt.capability_kinds,
        verified=True,
    )


def verify_frozen_publication(
    *,
    root: Path,
    benchmark: FrozenBenchmark,
    payloads: MaterializedPayloads | None = None,
) -> bool:
    """Read-only post-freeze verification of the published tree and seals.

    When ``payloads`` is supplied, every artifact byte is re-read from disk and
    every group checksum is recomputed against the receipt-bound hashes.
    """
    try:
        ensure_private_root(root)
        dataset_dir = _ds_path(root, benchmark.dataset_id)
        if not dataset_dir.is_dir() or dataset_dir.is_symlink():
            return False
        if dataset_dir.stat().st_mode & 0o777 != 0o700:
            return False
        for name in (MANIFEST_NAME, SEALED_POOL_MANIFEST_NAME, CHECKSUMS_NAME, RECEIPT_NAME):
            path = _ds_path(root, benchmark.dataset_id, name)
            if not path.is_file() or path.is_symlink():
                return False
            if path.stat().st_mode & 0o777 != 0o600:
                return False
        if bounded_read(dataset_dir / MANIFEST_NAME) != benchmark.dataset_manifest.canonical_bytes:
            return False
        if (
            bounded_read(dataset_dir / SEALED_POOL_MANIFEST_NAME)
            != benchmark.sealed_pool_manifest.canonical_bytes
        ):
            return False
        try:
            verify_manifest_chain(
                sealed_pool_manifest=benchmark.sealed_pool_manifest,
                dataset_manifest=benchmark.dataset_manifest,
            )
        except ManifestError:
            return False
        receipt_raw = bounded_read(dataset_dir / RECEIPT_NAME)
        if receipt_raw != benchmark.receipt.canonical_bytes:
            return False
        recomputed_receipt = _domain_hash(
            DOMAIN_FREEZE_RECEIPT, canonical_json_bytes(json.loads(receipt_raw.decode("utf-8")))
        )
        if recomputed_receipt != benchmark.receipt.receipt_sha256:
            return False
        if payloads is not None:
            _validate_payload_groups(payloads)
            for dirname, group, expected in (
                (
                    DIRNAME_PRIVATE,
                    payloads.private_payloads,
                    benchmark.receipt.private_payloads_sha256,
                ),
                (
                    DIRNAME_OPERATOR,
                    payloads.operator_payloads,
                    benchmark.receipt.operator_payloads_sha256,
                ),
                (DIRNAME_PILOT, payloads.pilot_payloads, benchmark.receipt.pilot_payloads_sha256),
                (
                    DIRNAME_SEALED_HOLDOUT,
                    payloads.holdout_payloads,
                    benchmark.receipt.holdout_payloads_sha256,
                ),
            ):
                _verify_group_from_disk(root, benchmark.dataset_id, dirname, group, expected)
        verify_capability_set(
            root=root,
            dataset_id=benchmark.dataset_id,
            expected_namespace=benchmark.namespace,
            group_payload_hashes={
                KIND_PRIVATE: benchmark.receipt.private_payloads_sha256,
                KIND_PILOT: benchmark.receipt.pilot_payloads_sha256,
                KIND_SEALED_HOLDOUT: benchmark.receipt.holdout_payloads_sha256,
            },
            group_artifact_counts={
                KIND_PRIVATE: benchmark.receipt.private_artifact_count,
                KIND_PILOT: benchmark.receipt.pilot_artifact_count,
                KIND_SEALED_HOLDOUT: benchmark.receipt.holdout_artifact_count,
            },
        )
    except (FreezeError, CapabilityError, FilesystemError, ManifestError, ValueError, OSError):
        return False
    return True


__all__ = [
    "DIRNAME_OPERATOR",
    "DIRNAME_PILOT",
    "DIRNAME_PRIVATE",
    "DIRNAME_SEALED_HOLDOUT",
    "DOMAIN_CORPUS_ID",
    "DOMAIN_FREEZE_RECEIPT",
    "DOMAIN_HOLDOUT_ID",
    "DOMAIN_PILOT_ID",
    "FORBIDDEN_SUMMARY_KEYS",
    "FreezeBindings",
    "FreezeError",
    "FreezeReceipt",
    "FrozenBenchmark",
    "run_freeze_transaction",
    "verify_frozen_publication",
]
