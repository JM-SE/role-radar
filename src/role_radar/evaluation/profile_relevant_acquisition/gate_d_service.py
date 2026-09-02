"""The single authoritative offline R2 Gate D service adapter."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from role_radar.collectors.policy import CollectionRunBudget
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    AcquisitionError,
    GateDResult,
    SourceCheckpoint,
    SyntheticCollectorFactory,
    SyntheticTransport,
    run_gate_d_broad_acquisition,
    verify_gate_d_reconciliations,
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


async def execute_gate_d_bounded_acquisition(
    *,
    request: GateDAuthorizationRequest,
    delegate: SyntheticTransport,
    collector_factory: SyntheticCollectorFactory,
    journal: AcquisitionJournal,
    checkpoints: Mapping[str, SourceCheckpoint] | None = None,
    before_after: Callable[[], tuple[dict[str, object], dict[str, object]]] | None = None,
) -> GateDServiceResult:
    """Validate, run the existing bounded runtime once, verify, and stop."""
    try:
        authorized: AuthorizedGateD = authorize_gate_d(request)
    except GateDAuthorizationError as exc:
        raise GateDServiceError(exc.code) from exc
    if not isinstance(delegate, SyntheticTransport):
        raise GateDServiceError("gate_d_synthetic_transport_required")
    if not isinstance(journal, AcquisitionJournal):
        raise GateDServiceError("gate_d_journal_required")
    budget = CollectionRunBudget(maximum=authorized.request.budget_units)
    # Replay debits are explicit and must reconcile with the durable journal;
    # the bounded runtime then skips only the supplied, matching checkpoints.
    for _ in range(journal.durable_intents()):
        if not budget.acquire():
            raise GateDServiceError("gate_d_budget_replay_mismatch")
    try:
        result = await run_gate_d_broad_acquisition(
            config=authorized.scaffold,
            source_plan=authorized.request.post_c_request.source_plan,
            delegate=delegate,
            budget=budget,
            evidence_root=authorized.request.evidence_root,
            journal=journal,
            checkpoints=dict(checkpoints) if checkpoints is not None else None,
            before_after=before_after,
            collector_factory=collector_factory,
            test_only_adapter=authorized.request.test_only_adapter,
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
    return GateDServiceResult(public, result)


run_gate_d_bounded_acquisition = execute_gate_d_bounded_acquisition

__all__ = [
    "GateDPublicResult",
    "GateDServiceError",
    "GateDServiceResult",
    "execute_gate_d_bounded_acquisition",
    "run_gate_d_bounded_acquisition",
]
