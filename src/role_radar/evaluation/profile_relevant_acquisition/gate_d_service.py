"""The single authoritative offline R2 Gate D service adapter."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from role_radar.collectors.policy import CollectionRunBudget
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    AcquisitionError,
    GateDResult,
    SourceCheckpoint,
    SyntheticCollectorFactory,
    _require_gate_d_transport,
    _seal_parent_pool,
    run_gate_d_broad_acquisition,
    verify_gate_d_reconciliations,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import (
    AuthorizedGateD,
    GateDAuthorizationError,
    GateDAuthorizationRequest,
    authorize_gate_d,
)
from role_radar.evaluation.profile_relevant_acquisition.journal import AcquisitionJournal


class GateDServiceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GateDPublicResult:
    operation_id: str
    preregistration_sha256: str
    source_plan_sha256: str
    pool_sha256: str
    manifest_sha256: str
    source_count: int
    attempted_count: int
    wire_attempts: int
    budget_status: str
    result: str
    code: str

    def as_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class GateDServiceResult:
    public: GateDPublicResult
    runtime: GateDResult


_REPLAY_CACHE: dict[tuple[object, ...], GateDServiceResult] = {}


async def execute_gate_d_bounded_acquisition(
    *,
    request: GateDAuthorizationRequest,
    delegate: object,
    collector_factory: SyntheticCollectorFactory,
    journal: AcquisitionJournal,
    checkpoints: Mapping[str, SourceCheckpoint] | Iterable[SourceCheckpoint] | None = None,
    before_after: Callable[[], tuple[dict[str, object], dict[str, object]]] | None = None,
    clock: Callable[[], datetime] | None = None,
    operational_approval: ExternalApprovalBinding | None = None,
    operational_approval_verifier: ExternalApprovalVerifier | None = None,
    operational: bool | None = None,
) -> GateDServiceResult:
    """Validate, run the existing bounded runtime once, verify, and stop."""
    try:
        is_operational = request.test_only_adapter is None
        if operational is not None and operational is not is_operational:
            raise GateDServiceError("gate_d_execution_mode_mismatch")
        if is_operational and (
            not isinstance(operational_approval, ExternalApprovalBinding)
            or operational_approval_verifier is None
        ):
            raise GateDServiceError("gate_d_operational_approval_required")
        authorized: AuthorizedGateD = authorize_gate_d(
            request, now=clock() if clock else None, allow_operational=is_operational
        )
    except GateDAuthorizationError as exc:
        raise GateDServiceError(exc.code) from exc
    try:
        _require_gate_d_transport(delegate)
    except AcquisitionError as exc:
        raise GateDServiceError(exc.code) from exc
    if not isinstance(journal, AcquisitionJournal):
        raise GateDServiceError("gate_d_journal_required")
    budget = CollectionRunBudget(maximum=authorized.request.budget_units)
    # Replay debits are explicit and must reconcile with the durable journal;
    # the bounded runtime then skips only the supplied, matching checkpoints.
    for _ in range(journal.durable_intents()):
        if not budget.acquire():
            raise GateDServiceError("gate_d_budget_replay_mismatch")
    checkpoint_map = (
        dict(checkpoints)
        if isinstance(checkpoints, Mapping)
        else {item.source_id: item for item in checkpoints}
        if checkpoints is not None
        else {}
    )
    replay_key = (
        authorized.request.operation_id,
        str(authorized.request.evidence_root),
        authorized.request.post_c_request.source_plan.source_plan_sha256,
        tuple(
            sorted(
                (item.source_id, item.wire_attempts, item.checkpoint_sha256)
                for item in checkpoint_map.values()
            )
        )
        if checkpoints is not None
        else (),
    )
    cached = _REPLAY_CACHE.get(replay_key)
    if cached is not None:
        # A process-local replay result is not permission to overwrite a sealed
        # artifact.  Re-run the no-replace seal check before accepting it.
        try:
            _seal_parent_pool(
                root=authorized.request.evidence_root,
                manifest=cached.runtime.manifest,
                observations=cached.runtime.observations,
            )
        except (AcquisitionError, ValueError) as exc:
            raise GateDServiceError(getattr(exc, "code", "gate_d_seal_failed")) from exc
        return cached
    try:
        result = await run_gate_d_broad_acquisition(
            config=authorized.scaffold,
            source_plan=authorized.request.post_c_request.source_plan,
            delegate=delegate,
            budget=budget,
            evidence_root=authorized.request.evidence_root,
            journal=journal,
            checkpoints=checkpoint_map or None,
            before_after=before_after,
            collector_factory=collector_factory,
            test_only_adapter=authorized.request.test_only_adapter,
            approval=operational_approval,
            approval_verifier=operational_approval_verifier,
            operational=is_operational,
        )
        verify_gate_d_reconciliations(
            manifest=result.manifest,
            journal=journal,
            budget=budget,
            checkpoints=result.checkpoints,
        )
    except (AcquisitionError, ValueError) as exc:
        raise GateDServiceError(getattr(exc, "code", "gate_d_failed")) from exc
    manifest_sha = hashlib.sha256(result.manifest.canonical_bytes).hexdigest()
    public = GateDPublicResult(
        operation_id=authorized.request.operation_id,
        preregistration_sha256=authorized.preregistration.preregistration_sha256,
        source_plan_sha256=authorized.request.post_c_request.source_plan.source_plan_sha256,
        pool_sha256=result.pool_sha256,
        manifest_sha256=manifest_sha,
        source_count=result.source_count,
        attempted_count=result.wire_attempts,
        wire_attempts=result.wire_attempts,
        budget_status="within_bound",
        result="completed",
        code="gate_d_bounded_acquisition_completed",
    )
    service_result = GateDServiceResult(public, result)
    _REPLAY_CACHE[
        (
            authorized.request.operation_id,
            str(authorized.request.evidence_root),
            authorized.request.post_c_request.source_plan.source_plan_sha256,
            tuple(
                sorted(
                    (item.source_id, item.wire_attempts, item.checkpoint_sha256)
                    for item in result.checkpoints
                )
            ),
        )
    ] = service_result
    return service_result


run_gate_d_bounded_acquisition = execute_gate_d_bounded_acquisition

__all__ = [
    "GateDPublicResult",
    "GateDServiceError",
    "GateDServiceResult",
    "execute_gate_d_bounded_acquisition",
    "run_gate_d_bounded_acquisition",
]
