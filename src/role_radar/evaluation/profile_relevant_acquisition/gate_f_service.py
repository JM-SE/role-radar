"""The sole public offline Gate F authority: materialize once, freeze once, stop."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from role_radar.evaluation.filesystem import bounded_read
from role_radar.evaluation.profile_relevance.contracts import MaterializedPayloads
from role_radar.evaluation.profile_relevant_acquisition.capability_seal import verify_capability_set
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    F10_1FHandoff,
    build_f_handoff,
)
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import (
    DIRNAME_OPERATOR,
    DIRNAME_PILOT,
    DIRNAME_PRIVATE,
    DIRNAME_SEALED_HOLDOUT,
    HOLDOUT_BINDING_LOGICAL_NAME,
    OPERATOR_LOGICAL_NAME,
    PILOT_BINDING_LOGICAL_NAME,
    FreezeBindings,
    FreezeError,
    FrozenBenchmark,
    _derive_split_ids,
    run_freeze_transaction,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_authorization import (
    GateFAuthorizationRequest,
    authorize_gate_f,
    freeze_bindings_for_request,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_input_adapter import (
    adapt_gate_f_input,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_materialization import (
    run_gate_f_materialization,
)
from role_radar.evaluation.profile_relevant_acquisition.manifest import (
    DOMAIN_DATASET_MANIFEST,
    DOMAIN_SEALED_POOL_MANIFEST,
    SCHEMA_DATASET_MANIFEST,
    SCHEMA_SEALED_POOL_MANIFEST,
    build_checksums_payload,
)


@dataclass(frozen=True, slots=True)
class GateFPublicResult:
    dataset_id: str
    namespace: str
    preview_input_sha256: str
    manifest_sha256: str
    receipt_sha256: str
    private_artifact_count: int
    pilot_artifact_count: int
    holdout_artifact_count: int
    capability_kinds: tuple[str, ...]
    status: str
    code: str

    def as_dict(self) -> dict[str, object]:
        return {
            "dataset_id": self.dataset_id,
            "namespace": self.namespace,
            "preview_input_sha256": self.preview_input_sha256,
            "manifest_sha256": self.manifest_sha256,
            "receipt_sha256": self.receipt_sha256,
            "private_artifact_count": self.private_artifact_count,
            "pilot_artifact_count": self.pilot_artifact_count,
            "holdout_artifact_count": self.holdout_artifact_count,
            "capability_kinds": self.capability_kinds,
            "status": self.status,
            "code": self.code,
        }


@dataclass(frozen=True, slots=True)
class GateFServiceResult:
    public: GateFPublicResult


def _public(benchmark: FrozenBenchmark, preview_input_sha256: str) -> GateFPublicResult:
    return GateFPublicResult(
        benchmark.dataset_id,
        benchmark.namespace,
        preview_input_sha256,
        benchmark.dataset_manifest.manifest_sha256,
        benchmark.receipt.receipt_sha256,
        benchmark.receipt.private_artifact_count,
        benchmark.receipt.pilot_artifact_count,
        benchmark.receipt.holdout_artifact_count,
        benchmark.capability_kinds,
        "completed",
        "gate_f_materialization_freeze_completed",
    )


def _replay_preflight(request: GateFAuthorizationRequest) -> GateFPublicResult | None:
    """Verify a complete existing publication without constructing anything."""
    target = request.destination_root / request.dataset_id
    if not target.exists() and not target.is_symlink():
        return None
    if target.is_symlink() or not target.is_dir():
        raise FreezeError("freeze_replay_conflict")
    required = ("manifest.json", "sealed_pool_manifest.json", "checksums.sha256", "receipt.json")
    paths = [target / name for name in required]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise FreezeError("freeze_replay_incomplete")
    try:
        manifest = json.loads((target / "sealed_pool_manifest.json").read_bytes())
        receipt_raw = (target / "receipt.json").read_bytes()
        receipt = json.loads(receipt_raw)
        dataset_manifest_raw = (target / "manifest.json").read_bytes()
        dataset_manifest = json.loads(dataset_manifest_raw)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise FreezeError("freeze_replay_conflict") from exc
    if (
        not isinstance(manifest, dict)
        or not isinstance(receipt, dict)
        or not isinstance(dataset_manifest, dict)
    ):
        raise FreezeError("freeze_replay_conflict")
    expected = freeze_bindings_for_request(request)
    comparisons = (
        (manifest.get("dataset_id"), expected.dataset_id),
        (manifest.get("pool_sha256"), expected.pool_sha256),
        (manifest.get("provenance_sha256"), expected.provenance_sha256),
        (manifest.get("source_plan_sha256"), expected.source_plan_sha256),
        (manifest.get("preview_input_sha256"), expected.preview_input_sha256),
        (manifest.get("selection_sha256"), expected.selection_sha256),
        (manifest.get("partition_sha256"), expected.partition_sha256),
        (manifest.get("pilot_membership_sha256"), expected.pilot_membership_sha256),
        (manifest.get("holdout_membership_sha256"), expected.holdout_membership_sha256),
        (manifest.get("observation_count"), expected.observation_count),
        (manifest.get("corpus_count"), expected.corpus_count),
        (manifest.get("pilot_count"), expected.pilot_count),
        (manifest.get("holdout_count"), expected.holdout_count),
    )
    if any(left != right for left, right in comparisons) or (
        manifest.get("inventory_sha256") != expected.inventory_sha256
        or manifest.get("domain") != DOMAIN_SEALED_POOL_MANIFEST
        or manifest.get("schema_version") != SCHEMA_SEALED_POOL_MANIFEST
    ):
        raise FreezeError("freeze_replay_conflict")
    if set(manifest) != {
        "corpus_count",
        "dataset_id",
        "domain",
        "holdout_count",
        "holdout_membership_sha256",
        "inventory_sha256",
        "observation_count",
        "partition_sha256",
        "pilot_count",
        "pilot_membership_sha256",
        "pool_sha256",
        "preview_input_sha256",
        "provenance_sha256",
        "schema_version",
        "selection_sha256",
        "source_plan_sha256",
    }:
        raise FreezeError("freeze_replay_conflict")
    manifest_canonical = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    dataset_canonical = json.dumps(
        dataset_manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if (
        target / "sealed_pool_manifest.json"
    ).read_bytes() != manifest_canonical or dataset_manifest_raw != dataset_canonical:
        raise FreezeError("freeze_replay_conflict")
    if dataset_manifest.get("dataset_id") != request.dataset_id:
        raise FreezeError("freeze_replay_conflict")
    if set(dataset_manifest) != {
        "dataset_id",
        "domain",
        "holdout_payloads_sha256",
        "operator_payloads_sha256",
        "pilot_payloads_sha256",
        "private_payloads_sha256",
        "schema_version",
        "sealed_pool_manifest_sha256",
    }:
        raise FreezeError("freeze_replay_conflict")
    if (
        dataset_manifest.get("domain") != DOMAIN_DATASET_MANIFEST
        or dataset_manifest.get("schema_version") != SCHEMA_DATASET_MANIFEST
    ):
        raise FreezeError("freeze_replay_conflict")
    if (
        receipt.get("dataset_id") != request.dataset_id
        or receipt.get("transaction_complete") is not True
    ):
        raise FreezeError("freeze_replay_incomplete")
    receipt_hash = _receipt_hash(receipt)
    dataset_manifest_hash = hashlib.sha256(
        b"role-radar:f10.1f:dataset-manifest:v1\0" + dataset_canonical
    ).hexdigest()
    sealed_manifest_hash = hashlib.sha256(
        b"role-radar:f10.1f:sealed-pool-manifest:v1\0" + manifest_canonical
    ).hexdigest()
    if (
        receipt.get("dataset_manifest_sha256") != dataset_manifest_hash
        or receipt.get("sealed_pool_manifest_sha256") != sealed_manifest_hash
        or dataset_manifest.get("sealed_pool_manifest_sha256") != sealed_manifest_hash
    ):
        raise FreezeError("freeze_replay_conflict")
    if receipt_raw != json.dumps(
        receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8"):
        raise FreezeError("freeze_replay_conflict")
    if set(receipt) != {
        "capability_kinds",
        "corpus_id",
        "dataset_id",
        "dataset_manifest_sha256",
        "domain",
        "holdout_artifact_count",
        "holdout_id",
        "holdout_payloads_sha256",
        "namespace",
        "operator_payloads_sha256",
        "pilot_artifact_count",
        "pilot_id",
        "pilot_payloads_sha256",
        "private_artifact_count",
        "private_payloads_sha256",
        "schema_version",
        "sealed_pool_manifest_sha256",
        "transaction_complete",
    }:
        raise FreezeError("freeze_replay_conflict")
    # Exact replay is read-only: validate every published byte and every seal.
    groups = {
        DIRNAME_PRIVATE: (
            "gate_decisions",
            "population",
            "preview",
            "provenance",
            "sampling_cells",
            "selection",
        ),
        DIRNAME_OPERATOR: (OPERATOR_LOGICAL_NAME,),
        DIRNAME_PILOT: (PILOT_BINDING_LOGICAL_NAME, "pilot_label_view"),
        DIRNAME_SEALED_HOLDOUT: (HOLDOUT_BINDING_LOGICAL_NAME, "holdout_sealed_view"),
    }
    group_hashes: dict[str, str] = {}
    group_counts: dict[str, int] = {}
    for directory, names in groups.items():
        actual = (
            set((target / directory).glob("*.json")) if (target / directory).is_dir() else set()
        )
        if len(actual) != len(names) or any(path.is_symlink() for path in actual):
            raise FreezeError("freeze_replay_incomplete")
        ordered = []
        for name in sorted(names):
            path = target / directory / f"{name}.json"
            if path not in actual or not path.is_file():
                raise FreezeError("freeze_replay_incomplete")
            raw = bounded_read(path)
            try:
                obj = json.loads(raw.decode())
                if (
                    not isinstance(obj, dict)
                    or json.dumps(
                        obj,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                    + b"\n"
                        != raw
                ):
                    raise ValueError
            except (OSError, UnicodeError, ValueError, TypeError):
                raise FreezeError("freeze_replay_conflict") from None
            ordered.append(raw)
        group_hashes[directory] = hashlib.sha256(b"".join(ordered)).hexdigest()
        group_counts[directory] = len(ordered)
    if (
        dataset_manifest.get("private_payloads_sha256") != group_hashes[DIRNAME_PRIVATE]
        or dataset_manifest.get("operator_payloads_sha256") != group_hashes[DIRNAME_OPERATOR]
        or dataset_manifest.get("pilot_payloads_sha256") != group_hashes[DIRNAME_PILOT]
        or dataset_manifest.get("holdout_payloads_sha256") != group_hashes[DIRNAME_SEALED_HOLDOUT]
        or receipt.get("namespace") != request.provenance.namespace
        or receipt.get("domain") != "role-radar:f10.1f:freeze-receipt:v1"
        or receipt.get("schema_version") != "f10.1f-freeze-receipt-v1"
        or receipt.get("private_payloads_sha256") != group_hashes[DIRNAME_PRIVATE]
        or receipt.get("operator_payloads_sha256") != group_hashes[DIRNAME_OPERATOR]
        or receipt.get("pilot_payloads_sha256") != group_hashes[DIRNAME_PILOT]
        or receipt.get("holdout_payloads_sha256") != group_hashes[DIRNAME_SEALED_HOLDOUT]
        or receipt.get("private_artifact_count") != group_counts[DIRNAME_PRIVATE]
        or receipt.get("pilot_artifact_count") != group_counts[DIRNAME_PILOT]
        or receipt.get("holdout_artifact_count") != group_counts[DIRNAME_SEALED_HOLDOUT]
    ):
        raise FreezeError("freeze_replay_conflict")
    corpus_id, pilot_id, holdout_id = _derive_split_ids(
        dataset_id=request.dataset_id,
        private_payloads_sha256=group_hashes[DIRNAME_PRIVATE],
        operator_payloads_sha256=group_hashes[DIRNAME_OPERATOR],
        pilot_payloads_sha256=group_hashes[DIRNAME_PILOT],
        holdout_payloads_sha256=group_hashes[DIRNAME_SEALED_HOLDOUT],
    )
    if (
        receipt.get("corpus_id") != corpus_id
        or receipt.get("pilot_id") != pilot_id
        or receipt.get("holdout_id") != holdout_id
    ):
        raise FreezeError("freeze_replay_conflict")
    try:
        checksums_raw = bounded_read(target / "checksums.sha256")
        checksums = json.loads(checksums_raw.decode())
        expected_checksums, _ = build_checksums_payload(
            dataset_id=request.dataset_id,
            sealed_pool_manifest_sha256=sealed_manifest_hash,
            private_payloads_sha256=group_hashes[DIRNAME_PRIVATE],
            operator_payloads_sha256=group_hashes[DIRNAME_OPERATOR],
            pilot_payloads_sha256=group_hashes[DIRNAME_PILOT],
            holdout_payloads_sha256=group_hashes[DIRNAME_SEALED_HOLDOUT],
        )
        if checksums_raw != expected_checksums or checksums.get("dataset_id") != request.dataset_id:
            raise FreezeError("freeze_replay_conflict")
        verify_capability_set(
            root=request.destination_root,
            dataset_id=request.dataset_id,
            expected_namespace=request.provenance.namespace,
            group_payload_hashes={
                "private": group_hashes[DIRNAME_PRIVATE],
                "pilot": group_hashes[DIRNAME_PILOT],
                "sealed_holdout": group_hashes[DIRNAME_SEALED_HOLDOUT],
            },
            group_artifact_counts={
                "private": group_counts[DIRNAME_PRIVATE],
                "pilot": group_counts[DIRNAME_PILOT],
                "sealed_holdout": group_counts[DIRNAME_SEALED_HOLDOUT],
            },
        )
    except FreezeError:
        raise
    except Exception as exc:
        raise FreezeError("freeze_replay_conflict") from exc
    if tuple(receipt.get("capability_kinds", ())) != ("pilot", "private", "sealed_holdout"):
        raise FreezeError("freeze_replay_conflict")
    return GateFPublicResult(
        request.dataset_id,
        request.provenance.namespace,
        expected.preview_input_sha256,
        dataset_manifest_hash,
        receipt_hash,
        int(receipt.get("private_artifact_count", 0)),
        int(receipt.get("pilot_artifact_count", 0)),
        int(receipt.get("holdout_artifact_count", 0)),
        tuple(receipt.get("capability_kinds", ())),
        "completed",
        "gate_f_materialization_freeze_replayed",
    )


def _receipt_hash(receipt: dict[str, object]) -> str:
    canonical = json.dumps(
        receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(b"role-radar:f10.1f:freeze-receipt:v1\0" + canonical).hexdigest()


def run_gate_f_materialization_freeze(
    *,
    request: GateFAuthorizationRequest,
    freeze_bindings: FreezeBindings,
    clock: Callable[[], datetime] | None = None,
    materializer: Callable[..., MaterializedPayloads] | None = None,
    freezer: Callable[..., FrozenBenchmark] | None = None,
) -> GateFServiceResult:
    """Validate and execute the bounded F flow.  No coordinator or successor is called."""
    authorized = authorize_gate_f(request, now=clock() if clock else None)
    expected_bindings = freeze_bindings_for_request(request)
    if freeze_bindings != expected_bindings:
        raise FreezeError("freeze_bindings_mismatch")
    replay = _replay_preflight(request)
    if replay is not None:
        return GateFServiceResult(replay)
    inputs, context = adapt_gate_f_input(authorized)
    # Recheck at the effect boundary; an authorization observed before pure
    # adaptation is not permission after its expiry.
    authorized = authorize_gate_f(request, now=clock() if clock else None)
    # The adapter is pure; this is the sole materializer call.
    materialize = run_gate_f_materialization if materializer is None else materializer
    payloads = materialize(
        approved_preview=context.expected_approved_preview,
        materialization_context=context,
        approved_result=authorized.request.gate_e_result,
        test_only_adapter=authorized.request.authorization.test_only_adapter,
    )
    handoff: F10_1FHandoff = build_f_handoff(
        operation_id=request.authorization.operation_id,
        challenge_sha256=request.authorization.challenge_sha256,
        provenance_sha256=request.provenance.provenance_sha256,
        artifact_class=ArtifactClass.SYNTHETIC,
        payloads=payloads,
    )
    # Final injected-clock check is immediately adjacent to the sole effect.
    authorize_gate_f(request, now=clock() if clock else None)
    freeze = run_freeze_transaction if freezer is None else freezer
    benchmark = freeze(
        root=request.destination_root,
        bindings=freeze_bindings,
        f_handoff=handoff,
        provenance=request.provenance,
        test_only_adapter=request.authorization.test_only_adapter,
    )
    return GateFServiceResult(_public(benchmark, inputs.preview_input_sha256))


__all__ = ["GateFPublicResult", "GateFServiceResult", "run_gate_f_materialization_freeze"]
