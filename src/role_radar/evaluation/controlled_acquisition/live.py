"""Gate-B-capable orchestration, kept behind explicit injected adapters.

This module performs no network or database work by itself.  The live entry
point supplies read-only inventory, source snapshots, collector tasks and the
operator acknowledgement.  This keeps the dangerous boundary reviewable and
testable with fakes before Gate B is authorized.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from role_radar.collectors.protocols import CollectorRuntime
from role_radar.evaluation.controlled_acquisition.acquisition import (
    CollectorTask,
    JournaledTransport,
    collect_sequential,
)
from role_radar.evaluation.controlled_acquisition.configuration import (
    ControlledAcquisitionConfig,
)
from role_radar.evaluation.controlled_acquisition.contracts import (
    LiveRunResult,
    OperationState,
    SourceCheckpoint,
)
from role_radar.evaluation.controlled_acquisition.journal import (
    Journal,
    JournalEvent,
    validate_transition,
)
from role_radar.evaluation.controlled_acquisition.snapshot import (
    SnapshotStore,
    materialize_selection,
    semantic_dataset_sha256,
)
from role_radar.evaluation.controlled_acquisition.source_plan import (
    SourcePlan,
    validate_live_plan,
)
from role_radar.evaluation.controlled_acquisition.workflow import seal_and_select


class SourceStateAdapter(Protocol):
    def checkpoint(self, source_ids: tuple[str, ...]) -> tuple[SourceCheckpoint, ...]: ...

    def assert_unchanged(self, checkpoint: tuple[SourceCheckpoint, ...]) -> None: ...

    def assert_all_disabled(self, checkpoint: tuple[SourceCheckpoint, ...]) -> None: ...

    def assert_global_disabled(self) -> None: ...


class ServiceGuard(Protocol):
    def prepare(self) -> None: ...

    def restore(self) -> None: ...


class HistoricalInventoryAdapter(Protocol):
    def capture_before_requests(self) -> None: ...

    def strong_keys(self) -> frozenset[str]: ...


class LiveAcknowledgementError(ValueError):
    """The acknowledgement does not match this exact plan/window challenge."""


def acknowledgement_challenge(
    *, plan_sha256: str, lookback_days: int, selection_as_of_utc: datetime
) -> str:
    as_of = selection_as_of_utc.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    return (
        f"I ACKNOWLEDGE F10.1 LIVE ACQUISITION PLAN {plan_sha256} "
        f"LOOKBACK {lookback_days} AS_OF {as_of}"
    )


def require_acknowledgement(
    supplied: str, *, plan_sha256: str, lookback_days: int, selection_as_of_utc: datetime
) -> None:
    expected = acknowledgement_challenge(
        plan_sha256=plan_sha256,
        lookback_days=lookback_days,
        selection_as_of_utc=selection_as_of_utc,
    )
    if not secrets.compare_digest(supplied, expected):
        raise LiveAcknowledgementError("live_acknowledgement_mismatch")


@dataclass(frozen=True, slots=True)
class LiveAdapters:
    source_state: SourceStateAdapter
    inventory: HistoricalInventoryAdapter
    tasks: Callable[[SourcePlan], Iterable[CollectorTask]]
    runtime: CollectorRuntime
    snapshot_store: SnapshotStore
    journal: Journal
    prepare_services: Callable[[], None]
    restore_services: Callable[[], None]
    assert_runtime_safe: Callable[[], None] | None = None
    assert_profile: Callable[[SourcePlan], None] | None = None
    assert_deployment: Callable[[SourcePlan], None] | None = None


class LiveAcquisition:
    """A sequential saga.  It never writes product database rows."""

    def __init__(self, *, config: ControlledAcquisitionConfig, adapters: LiveAdapters) -> None:
        self.config = config
        self.adapters = adapters

    async def run(
        self,
        *,
        plan: SourcePlan,
        profile_sha256: str,
        acknowledgement: str,
        source_ids: tuple[str, ...],
        selection_as_of_utc: datetime,
    ) -> LiveRunResult:
        operation_id = hashlib.sha256(
            f"f10.1:{plan.sha256}:{selection_as_of_utc.isoformat()}".encode()
        ).hexdigest()[:32]
        checkpoint: tuple[SourceCheckpoint, ...] = ()
        state = OperationState.PLANNED
        services_prepared = False
        try:
            self.config.require_approved_run()
            approved_as_of = validate_live_plan(plan)
            if approved_as_of != selection_as_of_utc.astimezone(UTC):
                raise ValueError("selection_as_of_mismatch")
            if profile_sha256 != plan.profile_sha256:
                raise ValueError("profile_hash_mismatch")
            if plan.lookback_days != self.config.lookback_days:
                raise ValueError("lookback_mismatch")
            if self.adapters.assert_profile is not None:
                self.adapters.assert_profile(plan)
            if self.adapters.assert_deployment is not None:
                self.adapters.assert_deployment(plan)
            require_acknowledgement(
                acknowledgement,
                plan_sha256=plan.sha256,
                lookback_days=plan.lookback_days,
                selection_as_of_utc=selection_as_of_utc,
            )
            self.adapters.prepare_services()
            services_prepared = True
            if self.adapters.assert_runtime_safe is not None:
                self.adapters.assert_runtime_safe()
            checkpoint = self.adapters.source_state.checkpoint(source_ids)
            self.adapters.source_state.assert_all_disabled(checkpoint)
            self.adapters.source_state.assert_global_disabled()
            if any(item.enabled for item in checkpoint):
                raise ValueError("source_must_be_disabled")
            self._transition(state, OperationState.PLAN_APPROVED, operation_id)
            state = OperationState.PLAN_APPROVED
            self._transition(state, OperationState.ACQUIRING, operation_id)
            state = OperationState.ACQUIRING
            if self.adapters.journal.has_pending_request(operation_id):
                self._record(operation_id, "indeterminate", "request_result_missing")
                return LiveRunResult(
                    operation_id,
                    OperationState.INDETERMINATE,
                    error_code="request_result_missing",
                )
            self.adapters.inventory.capture_before_requests()

            observations = await collect_sequential(
                self.adapters.tasks(plan),
                self.adapters.runtime,
                runtime_factory=lambda task: self._runtime_for_task(
                    task, operation_id
                ),
            )
            self._transition(state, OperationState.POOL_SEALED, operation_id)
            state = OperationState.POOL_SEALED
            result = seal_and_select(
                observations,
                config=self.config,
                selection_as_of_utc=selection_as_of_utc,
                profile_sha256=profile_sha256,
                historical_keys=self.adapters.inventory.strong_keys(),
            )
            if result.status != "selected":
                self._transition(state, OperationState.FAILED, operation_id)
                return LiveRunResult(
                    operation_id,
                    OperationState.FAILED,
                    observations,
                    result,
                    "insufficient",
                )
            self._transition(state, OperationState.SELECTED, operation_id)
            state = OperationState.SELECTED
            dataset_lines, provenance_lines, label_lines = materialize_selection(
                result.selected, dataset_seed=plan.sha256
            )
            semantic_hash = semantic_dataset_sha256(
                header={"profile_sha256": profile_sha256, "plan_sha256": plan.sha256},
                dataset_lines=dataset_lines,
                provenance_lines=provenance_lines,
                label_lines=label_lines,
            )
            self._transition(state, OperationState.STAGED, operation_id)
            state = OperationState.STAGED
            target = self.adapters.snapshot_store.publish(
                dataset_id=semantic_hash,
                dataset_lines=dataset_lines,
                provenance_lines=provenance_lines,
                label_lines=label_lines,
                internal={
                    "operation_id": operation_id,
                    "semantic_dataset_sha256": semantic_hash,
                    "profile_sha256": profile_sha256,
                    "plan_sha256": plan.sha256,
                    "selection_as_of_utc": selection_as_of_utc,
                    "count": len(result.selected),
                },
            )
            if not self.adapters.snapshot_store.verify(target.name):
                raise ValueError("snapshot_verification_failed")
            self._transition(state, OperationState.VERIFIED, operation_id)
            state = OperationState.VERIFIED
            self._transition(state, OperationState.PUBLISHED, operation_id)
            state = OperationState.PUBLISHED
            self._transition(state, OperationState.COMPLETED, operation_id)
            return LiveRunResult(operation_id, OperationState.COMPLETED, observations, result)
        except LiveAcknowledgementError as exc:
            self._record(operation_id, "blocked", "live_acknowledgement_mismatch")
            return LiveRunResult(operation_id, OperationState.FAILED, error_code=str(exc))
        except Exception:
            self._record(operation_id, "failed", "live_run_failed")
            return LiveRunResult(operation_id, OperationState.FAILED, error_code="live_run_failed")
        finally:
            if services_prepared:
                try:
                    if checkpoint:
                        self.adapters.source_state.assert_unchanged(checkpoint)
                finally:
                    self.adapters.restore_services()

    def _transition(
        self, current: OperationState, next_state: OperationState, operation_id: str
    ) -> None:
        validate_transition(current, next_state)
        self._record(operation_id, "state", next_state.value)

    def _runtime_for_task(self, task: CollectorTask, operation_id: str) -> CollectorRuntime:
        return CollectorRuntime(
            transport=JournaledTransport(
                operation_id=operation_id,
                source_id=task.snapshot.source_id,
                journal=self.adapters.journal,
                transport=self.adapters.runtime.transport,
            ),
            clock=self.adapters.runtime.clock,
            sleeper=self.adapters.runtime.sleeper,
            budget=self.adapters.runtime.budget,
        )

    def _record(self, operation_id: str, kind: str, code: str) -> None:
        self.adapters.journal.append(
            JournalEvent(kind, code, code, {"operation_id": operation_id})
        )
