"""The sole public offline Gate F authority: materialize once, freeze once, stop."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    F10_1FHandoff,
    build_f_handoff,
)
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import (
    FreezeBindings,
    FreezeError,
    FrozenBenchmark,
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
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


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
    if any(left != right for left, right in comparisons):
        raise FreezeError("freeze_replay_conflict")
    manifest_canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    dataset_canonical = json.dumps(
        dataset_manifest, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if (
        target / "sealed_pool_manifest.json"
    ).read_bytes() != manifest_canonical or dataset_manifest_raw != dataset_canonical:
        raise FreezeError("freeze_replay_conflict")
    if dataset_manifest.get("dataset_id") != request.dataset_id:
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
    ):
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
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(b"role-radar:f10.1f:freeze-receipt:v1\0" + canonical).hexdigest()


def run_gate_f_materialization_freeze(
    *,
    request: GateFAuthorizationRequest,
    freeze_bindings: FreezeBindings,
    clock: Callable[[], datetime] | None = None,
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
    payloads = run_gate_f_materialization(
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
    benchmark = run_freeze_transaction(
        root=request.destination_root,
        bindings=freeze_bindings,
        f_handoff=handoff,
        provenance=request.provenance,
        test_only_adapter=request.authorization.test_only_adapter,
    )
    return GateFServiceResult(_public(benchmark, inputs.preview_input_sha256))


__all__ = ["GateFPublicResult", "GateFServiceResult", "run_gate_f_materialization_freeze"]
