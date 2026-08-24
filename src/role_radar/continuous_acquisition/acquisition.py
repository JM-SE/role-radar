"""Sequential acquisition orchestration over an immutable source snapshot."""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from role_radar.collectors.outcomes import CollectionFailure, CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.continuous_acquisition.contracts import (
    AcquisitionRunResult,
    AcquisitionRunState,
    AcquisitionSourceOutcome,
    JobCounters,
    OperationState,
    RequestBudget,
    SourceCollector,
    SourceSnapshot,
)
from role_radar.continuous_acquisition.persistence import OfferPersistence
from role_radar.continuous_acquisition.policy import aggregate_outcomes
from role_radar.continuous_acquisition.repositories import FenceLostError, RunRepository
from role_radar.continuous_acquisition.scheduling import rotate_sources
from role_radar.domain.dto import RawJob


@dataclass(frozen=True, slots=True)
class AcquisitionService:
    """Provider-independent runner; persistence and collectors are injected."""

    run_repository: RunRepository
    snapshots: tuple[SourceSnapshot, ...]
    collectors: dict[str, SourceCollector]
    as_of_utc: datetime
    owner: str
    budget: RequestBudget | None = None

    def run(self, *, slot_key: str) -> AcquisitionRunResult:
        ordered_ids = rotate_sources(tuple(source.source_id for source in self.snapshots), day=self.as_of_utc)
        by_id = {source.source_id: source for source in self.snapshots}
        run = self.run_repository.claim_acquisition(slot_key=slot_key, policy_version="continuous-acquisition-v1", snapshots=self.snapshots, owner=self.owner)
        self.run_repository.session.commit()
        if run.state not in {"planned", "running"}:
            return AcquisitionRunResult(
                state=AcquisitionRunState(run.state),
                new_jobs=run.created_count,
                outcomes=(),
                counters=JobCounters(
                    observed=run.observed_count,
                    created=run.created_count,
                    duplicate=run.duplicate_count,
                    stale=run.stale_count,
                    invalid=run.invalid_count,
                    conflict=run.conflict_count,
                ),
                terminal_code=run.terminal_code,
            )
        budget = self.budget or RequestBudget()
        wire_budget = CollectionRunBudget(maximum=100)
        for collector in self.collectors.values():
            setter = getattr(collector, "set_budget", None)
            if setter is not None:
                setter(wire_budget)
        outcomes: list[AcquisitionSourceOutcome] = []
        for source_id in ordered_ids:
            source = by_id[source_id]
            if budget.exhausted:
                outcomes.append(AcquisitionSourceOutcome(source_id, OperationState.TRUNCATED, usable=False, error_code="budget_exhausted"))
                break
            try:
                self.run_repository.fence(run.id, owner=self.owner, generation=run.fencing_generation)
                operation = self.run_repository.create_operation(run.id, source, owner=self.owner, generation=run.fencing_generation)
                self.run_repository.session.commit()
            except FenceLostError:
                return AcquisitionRunResult(AcquisitionRunState.INDETERMINATE, 0, tuple(outcomes), terminal_code="fence_lost")
            try:
                if not budget.reserve():
                    outcomes.append(AcquisitionSourceOutcome(source_id, OperationState.TRUNCATED, usable=False, error_code="budget_exhausted"))
                    break
                if not budget.begin_attempt():
                    break
                collected = self.collectors[source.source_type](source)
                if inspect.isawaitable(collected):
                    # Preserve sync/fake compatibility while making the real
                    # async collector seam usable by existing callers.
                    collected = asyncio.run(cast(Any, collected))
                collected_result = cast(CollectionFailure | CollectionSuccess | tuple[RawJob, ...], collected)
                raw_jobs: tuple[RawJob, ...]
                if isinstance(collected_result, CollectionFailure):
                    counters = JobCounters()
                    error_code = collected_result.error_code.value
                    state = OperationState.FAILED
                    usable = True
                    raw_jobs = ()
                elif isinstance(collected_result, CollectionSuccess):
                    counters = JobCounters()
                    raw_jobs = collected_result.jobs
                    error_code = None
                    state = OperationState.EMPTY if not raw_jobs else OperationState.SUCCEEDED
                    usable = True
                else:
                    raw_jobs = collected_result
                    counters = JobCounters()
                    error_code = None
                    state = OperationState.EMPTY if not raw_jobs else OperationState.SUCCEEDED
                    usable = True
                budget.complete()
                counters = JobCounters()
                writer = OfferPersistence(self.run_repository.session, as_of_utc=self.as_of_utc)
                for raw in raw_jobs:
                    self.run_repository.fence(run.id, owner=self.owner, generation=run.fencing_generation)
                    disposition = writer.persist(raw, source=source, run_id=run.id, operation_id=operation.id, assert_fence=lambda: self.run_repository.fence(run.id, owner=self.owner, generation=run.fencing_generation))
                    counters = _increment(counters, disposition)
                outcome = AcquisitionSourceOutcome(source_id, state, counters, usable=usable, error_code=error_code)
                self.run_repository.finalize_operation(operation.id, owner=self.owner, generation=run.fencing_generation, result_state=outcome.state.value, intent_state=outcome.state.value, result_code=error_code, observed_count=counters.observed, created_count=counters.created, duplicate_count=counters.duplicate, stale_count=counters.stale, invalid_count=counters.invalid, conflict_count=counters.conflict)
                outcomes.append(outcome)
                self.run_repository.session.commit()
            except FenceLostError:
                self.run_repository.session.rollback()
                return AcquisitionRunResult(AcquisitionRunState.INDETERMINATE, 0, tuple(outcomes), terminal_code="fence_lost")
            except Exception:
                self.run_repository.session.rollback()
                try:
                    self.run_repository.finalize_operation(
                        operation.id,
                        owner=self.owner,
                        generation=run.fencing_generation,
                        result_state=OperationState.FAILED.value,
                        intent_state=OperationState.FAILED.value,
                        result_code="operation_failed",
                    )
                    self.run_repository.session.commit()
                except FenceLostError:
                    self.run_repository.session.rollback()
                    return AcquisitionRunResult(AcquisitionRunState.INDETERMINATE, 0, tuple(outcomes), terminal_code="fence_lost")
                outcomes.append(AcquisitionSourceOutcome(source_id, OperationState.FAILED, usable=True, error_code="operation_failed"))
        result = aggregate_outcomes(tuple(outcomes))
        self.run_repository.finalize_run(
            run.id,
            owner=self.owner,
            generation=run.fencing_generation,
            state=result.state.value,
            created_count=result.counters.created,
            observed_count=result.counters.observed,
            duplicate_count=result.counters.duplicate,
            stale_count=result.counters.stale,
            invalid_count=result.counters.invalid,
            conflict_count=result.counters.conflict,
            reserved_requests=budget.counter.reserved,
            attempted_requests=budget.counter.attempted,
            completed_requests=budget.counter.completed,
            truncated_requests=budget.counter.truncated,
        )
        self.run_repository.session.commit()
        return result

    async def run_async(self, *, slot_key: str) -> AcquisitionRunResult:
        """Run the sequential acquisition loop without blocking the event loop."""
        return await asyncio.to_thread(self.run, slot_key=slot_key)


def _increment(counters: JobCounters, disposition: str) -> JobCounters:
    if disposition == "created":
        return JobCounters(counters.observed + 1, counters.created + 1, counters.duplicate, counters.stale, counters.invalid, counters.conflict)
    if disposition == "duplicate":
        return JobCounters(counters.observed + 1, counters.created, counters.duplicate + 1, counters.stale, counters.invalid, counters.conflict)
    if disposition == "identity_conflict":
        return JobCounters(counters.observed + 1, counters.created, counters.duplicate, counters.stale, counters.invalid, counters.conflict + 1)
    if disposition.startswith("freshness_") or disposition in {"provider_closed", "expired_at_selection_time"}:
        return JobCounters(counters.observed + 1, counters.created, counters.duplicate, counters.stale + 1, counters.invalid, counters.conflict)
    return JobCounters(counters.observed + 1, counters.created, counters.duplicate, counters.stale, counters.invalid + 1, counters.conflict)
