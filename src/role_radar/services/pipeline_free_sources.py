"""Prepare, execute, and finalize scheduled free-source tasks."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionMetrics,
    CollectionSuccess,
    CollectorFailureCode,
)
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, JobCollector, SourceSnapshot
from role_radar.collectors.registry import (
    CollectorContext,
    SourceSnapshotModel,
    create_collector,
    validate_snapshot,
)
from role_radar.db.models import JobSearchRun, Source
from role_radar.domain.enums import DiscoveryMode, SourceType
from role_radar.free_sources.contracts import (
    DueSource,
    FreeSourceCounters,
    FreeSourceExecution,
    FreeSourcePlan,
    FreeSourceTask,
    sanitized_result,
)
from role_radar.free_sources.due_policy import reserve_one_slot, utc
from role_radar.free_sources.terms import JobicyTermsAcceptance, validate_jobicy_terms
from role_radar.matching.transient_clarification import MAX_ATTEMPTS_PER_RUN
from role_radar.repositories.source_poll_states import SourcePollStateRepository
from role_radar.services.acquired_job_writer import AcquiredJobWriter


class PipelineFreeSourcesService:
    """No SQLAlchemy object is retained across the async collection boundary."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        terms: JobicyTermsAcceptance | None = None,
        collector_factory: Callable[[SourceSnapshot], JobCollector] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._terms = terms
        self._collector_factory = collector_factory
        self._clock = clock or (lambda: datetime.now(UTC))

    def prepare(self, run_id: str) -> FreeSourcePlan:
        now = utc(self._clock())
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            scheduled = DiscoveryMode(getattr(run.discovery_mode, "value", run.discovery_mode)) == (
                DiscoveryMode.SCHEDULED_DUE
            )
            if not scheduled:
                session.commit()
                return FreeSourcePlan(run_id, (), FreeSourceCounters(), False)

            poll = SourcePollStateRepository(session)
            tasks: list[FreeSourceTask] = []
            due_count = 0
            deferred_count = 0
            for source in session.scalars(
                select(Source)
                .where(
                    Source.type == SourceType.JOBICY,
                    Source.enabled.is_(True),
                    Source.archived_at.is_(None),
                )
                .order_by(Source.id)
            ):
                state = poll.ensure_jobicy(source.id, now=now)
                replay_slot = (
                    _stored_utc(state.last_reserved_slot)
                    if state.operation_id is not None
                    and state.operation_id.startswith(f"free:{run_id}:")
                    and state.last_request_at is None
                    and state.last_reserved_slot is not None
                    else None
                )
                next_due = _stored_utc(state.next_due_at)
                current_slot = (
                    _stored_utc(state.last_reserved_slot)
                    if state.last_reserved_slot is not None
                    else None
                )
                due_slot = replay_slot or (
                    current_slot
                    if (
                        current_slot is not None
                        and state.last_request_at is None
                        and current_slot <= now < next_due
                    )
                    else reserve_one_slot(next_due, now)
                )
                if due_slot is None:
                    continue
                due_count += 1
                terms_error = validate_jobicy_terms(self._terms, now=now)
                due_source = DueSource(
                    source_id=source.id,
                    source_type=SourceType.JOBICY.value,
                    source_key=source.source_key,
                    name=source.name,
                    configuration=MappingProxyType(dict(source.configuration or {})),
                    configuration_version=source.configuration_version,
                    due_slot=utc(due_slot),
                )
                if terms_error is not None:
                    deferred_count += 1
                    tasks.append(FreeSourceTask(due_source, None, None, terms_error))
                    continue
                try:
                    validate_snapshot(
                        SourceSnapshotModel(
                            source_id=source.id,
                            source_type=SourceType.JOBICY,
                            name=source.name,
                            configuration=dict(source.configuration or {}),
                            source_key=source.source_key,
                            configuration_version=source.configuration_version,
                        ).as_snapshot()
                    )
                except ValueError:
                    deferred_count += 1
                    tasks.append(FreeSourceTask(due_source, None, None, "config"))
                    continue
                reservation = poll.reserve_jobicy(source.id, run_id=run_id, now=now)
                if reservation.status in {"reserved", "reused"}:
                    tasks.append(
                        FreeSourceTask(
                            due_source,
                            reservation.reservation_id,
                            reservation.operation_id,
                        )
                    )
                else:
                    deferred_count += 1
                    tasks.append(
                        FreeSourceTask(
                            due_source,
                            None,
                            None,
                            (
                                "already_reserved"
                                if reservation.status == "already_reserved"
                                else reservation.status
                            ),
                        )
                    )
            session.commit()
            return FreeSourcePlan(
                run_id,
                tuple(tasks),
                FreeSourceCounters(
                    due=due_count,
                    attempted=0,
                    ok=0,
                    failed=0,
                    deferred=deferred_count,
                ),
                True,
            )

    async def execute(self, task: FreeSourceTask) -> FreeSourceExecution:
        if task.deferred_code is not None:
            return FreeSourceExecution(task, None, False, task.deferred_code)
        if not task.reserved or task.operation_id is None:
            return FreeSourceExecution(task, None, False, "already_reserved")

        with self._session_factory() as session:
            started = SourcePollStateRepository(session).mark_request_started(
                task.source.source_id,
                operation_id=task.operation_id,
                now=utc(self._clock()),
            )
            session.commit()
        if not started:
            return FreeSourceExecution(task, None, False, "already_reserved")

        snapshot = SourceSnapshot(
            source_id=task.source.source_id,
            source_type=task.source.source_type,
            name=task.source.name,
            configuration=task.source.configuration,
            source_key=task.source.source_key,
            configuration_version=task.source.configuration_version,
        )
        try:
            collector = (
                self._collector_factory(snapshot)
                if self._collector_factory is not None
                else create_collector(snapshot, CollectorContext(budget=CollectionRunBudget(1)))
            )
            runtime = CollectorRuntime(budget=CollectionRunBudget(1))
            method: Any = collector.collect
            value = (
                await method(snapshot)
                if len(inspect.signature(method).parameters) == 1
                else await method(snapshot, runtime)
            )
            if not isinstance(value, (CollectionSuccess, CollectionFailure)):
                raise TypeError("collector returned an invalid outcome")
            return FreeSourceExecution(task, value, True)
        except asyncio.CancelledError:
            raise
        except Exception:
            return FreeSourceExecution(
                task,
                CollectionFailure(
                    status="failed",
                    error_code=CollectorFailureCode.INTERNAL,
                    metrics=CollectionMetrics(logical_requests=1, logical_pages=1),
                ),
                True,
            )

    def finalize(self, run_id: str, execution: FreeSourceExecution) -> None:
        task = execution.task
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            source = session.get(Source, task.source.source_id)
            if run is None or source is None:
                raise LookupError("free-source finalization target not found")
            if execution.deferred_code is not None:
                self._set_result(
                    run,
                    source.id,
                    sanitized_result(
                        status="deferred",
                        counters=FreeSourceCounters(due=1, deferred=1),
                        error_code=execution.deferred_code,
                    ),
                )
                session.commit()
                return
            if task.operation_id is None or execution.outcome is None:
                raise LookupError("free-source execution is incomplete")
            outcome = execution.outcome
            if isinstance(outcome, CollectionFailure):
                SourcePollStateRepository(session).finalize(
                    source.id,
                    operation_id=task.operation_id,
                    now=utc(self._clock()),
                    success=False,
                    error_code=outcome.error_code.value,
                )
                source.last_error_at = utc(self._clock())
                source.last_error_code = outcome.error_code.value
                self._set_result(
                    run,
                    source.id,
                    sanitized_result(
                        status="failed",
                        counters=FreeSourceCounters(due=1, attempted=1, failed=1),
                        error_code=outcome.error_code.value,
                    ),
                )
                session.commit()
                return

            try:
                written = AcquiredJobWriter(session).write(
                    run_id=run_id,
                    source_id=source.id,
                    raw_jobs=outcome.jobs,
                    acquisition="free_source",
                    max_clarification_attempts=MAX_ATTEMPTS_PER_RUN,
                )
                SourcePollStateRepository(session).finalize(
                    source.id,
                    operation_id=task.operation_id,
                    now=utc(self._clock()),
                    success=True,
                )
                source.last_success_at = utc(self._clock())
                source.last_error_code = None
                self._set_result(
                    run,
                    source.id,
                    sanitized_result(
                        status=outcome.status,
                        counters=FreeSourceCounters(due=1, attempted=1, ok=1),
                        collected=len(outcome.jobs),
                        new_jobs=written.new_jobs,
                        duplicates=written.duplicates,
                        prefiltered=written.prefiltered,
                        profile_rejected=written.profile_rejected,
                        profile_reason_counts=dict(written.profile_reason_counts),
                        clarification_attempts=written.clarification_attempts,
                    ),
                )
                session.commit()
            except Exception:
                session.rollback()
                self._record_persistence_failure(run_id, task)
                raise

    def _record_persistence_failure(self, run_id: str, task: FreeSourceTask) -> None:
        if task.operation_id is None:
            return
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            source = session.get(Source, task.source.source_id)
            if run is None or source is None:
                raise LookupError("free-source persistence failure target not found")
            SourcePollStateRepository(session).finalize(
                source.id,
                operation_id=task.operation_id,
                now=utc(self._clock()),
                success=False,
                error_code=CollectorFailureCode.PERSISTENCE.value,
            )
            source.last_error_at = utc(self._clock())
            source.last_error_code = CollectorFailureCode.PERSISTENCE.value
            self._set_result(
                run,
                source.id,
                sanitized_result(
                    status="failed",
                    counters=FreeSourceCounters(due=1, attempted=1, failed=1),
                    error_code=CollectorFailureCode.PERSISTENCE.value,
                ),
            )
            session.commit()

    @staticmethod
    def _set_result(run: JobSearchRun, source_id: str, result: dict[str, Any]) -> None:
        values = dict(run.source_results_json or {})
        values[source_id] = result
        run.source_results_json = values


# Short alias for callers that use the decomposition name directly.
PipelineFreeSources = PipelineFreeSourcesService


def _stored_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
