"""The sole public offline Gate F authority: materialize once, freeze once, stop."""

from __future__ import annotations

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
    FrozenBenchmark,
    run_freeze_transaction,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_authorization import (
    GateFAuthorizationRequest,
    authorize_gate_f,
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
    frozen: FrozenBenchmark


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


def run_gate_f_materialization_freeze(
    *,
    request: GateFAuthorizationRequest,
    freeze_bindings: FreezeBindings,
    clock: Callable[[], datetime] | None = None,
) -> GateFServiceResult:
    """Validate and execute the bounded F flow.  No coordinator or successor is called."""
    authorized = authorize_gate_f(request, now=clock() if clock else None)
    inputs, context = adapt_gate_f_input(authorized)
    # Recheck at the effect boundary; an authorization observed before pure
    # adaptation is not permission after its expiry.
    authorized = authorize_gate_f(request, now=clock() if clock else None)
    # The adapter is pure; this is the sole materializer call.
    payloads = run_gate_f_materialization(
        approved_preview=context.expected_approved_preview,
        materialization_context=context,
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
    return GateFServiceResult(_public(benchmark, inputs.preview_input_sha256), benchmark)


__all__ = ["GateFPublicResult", "GateFServiceResult", "run_gate_f_materialization_freeze"]
