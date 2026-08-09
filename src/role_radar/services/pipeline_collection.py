"""Prepare/execute/finalize collection with short, independent DB sessions."""

import asyncio
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionMetrics,
    CollectionOutcome,
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
from role_radar.config import Settings
from role_radar.db.models import JobSearchRun, Source
from role_radar.domain.enums import JobSearchRunStatus, SourceType
from role_radar.services.acquired_job_writer import AcquiredJobWriter


@dataclass(frozen=True, slots=True)
class CollectionResult:
    source_id: str
    outcome: CollectionOutcome

    @property
    def jobs(self) -> tuple[Any, ...]:
        return self.outcome.jobs if isinstance(self.outcome, CollectionSuccess) else ()

    @property
    def error_code(self) -> str | None:
        return (
            self.outcome.error_code.value
            if isinstance(self.outcome, CollectionFailure)
            else None
        )


class PipelineCollectionService:
    """No ORM object is retained by or passed into async execute."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        collector_factory: Callable[[SourceSnapshot], JobCollector] | None = None,
        settings: Settings | None = None,
        run_budget: CollectionRunBudget | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._collector_factory = collector_factory
        self._settings = settings or Settings()
        self._run_budget = run_budget or CollectionRunBudget(100)

    def start_run_budget(self) -> None:
        self._run_budget = CollectionRunBudget(100)

    def prepare(self, run_id: str) -> tuple[SourceSnapshot, ...]:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            if run.source_snapshot_json is not None:
                snapshots = tuple(
                    SourceSnapshotModel.model_validate(item).as_snapshot()
                    for item in run.source_snapshot_json
                )
            else:
                sources = list(
                    session.scalars(
                        select(Source)
                        .where(Source.enabled.is_(True), Source.archived_at.is_(None))
                        .order_by(Source.name, Source.id)
                    )
                )
                snapshots = tuple(
                    SourceSnapshotModel(
                        source_id=source.id,
                        source_type=SourceType(source.type),
                        name=source.name,
                        configuration=dict(source.configuration or {}),
                        source_key=source.source_key,
                        configuration_version=source.configuration_version,
                    ).as_snapshot()
                    for source in sources
                )
                snapshots = tuple(validate_snapshot(snapshot) for snapshot in snapshots)
            run.source_snapshot_json = run.source_snapshot_json or [
                SourceSnapshotModel(
                    source_id=item.source_id,
                    source_type=SourceType(item.source_type),
                    name=item.name,
                    configuration=dict(item.configuration),
                    source_key=item.source_key,
                    configuration_version=item.configuration_version,
                ).model_dump(mode="json")
                for item in snapshots
            ]
            run.status = JobSearchRunStatus.COLLECTING
            run.started_at = run.started_at or datetime.now(UTC)
            session.commit()
            return snapshots

    async def execute(self, snapshot: SourceSnapshot) -> CollectionResult:
        try:
            collector = self._make_collector(snapshot)
            runtime = CollectorRuntime(budget=self._run_budget)
            method: Any = collector.collect
            # Compatibility collectors from F2/F5 accepted only the snapshot.
            parameter_count = len(inspect.signature(method).parameters)
            value = (
                await method(snapshot)
                if parameter_count == 1
                else await method(snapshot, runtime)
            )
            outcome = self._legacy_outcome(value) if isinstance(value, list) else value
            if not isinstance(outcome, (CollectionSuccess, CollectionFailure)):
                raise TypeError("collector returned an invalid outcome")
            return CollectionResult(snapshot.source_id, outcome)
        except asyncio.CancelledError:
            raise
        except Exception:
            failure = CollectionFailure(
                status="failed",
                error_code=CollectorFailureCode.INTERNAL,
                metrics=CollectionMetrics(),
            )
            return CollectionResult(snapshot.source_id, failure)

    def finalize(self, run_id: str, result: CollectionResult) -> None:
        try:
            with self._session_factory() as session:
                self._finalize_in_session(session, run_id, result)
                session.commit()
        except Exception:
            self._record_persistence_failure(run_id, result)
            raise

    def _finalize_in_session(self, session: Session, run_id: str, result: CollectionResult) -> None:
        run = session.get(JobSearchRun, run_id)
        if run is None:
            raise LookupError("run not found")
        source = session.get(Source, result.source_id)
        if source is None:
            raise LookupError("source not found")
        projected = self._historical_projection(result.outcome)
        if isinstance(result.outcome, CollectionFailure):
            source.last_error_at = datetime.now(UTC)
            source.last_error_code = result.outcome.error_code.value
            projected["status"] = "failed"
            projected["failed"] = 1
            self._set_result(run, result.source_id, projected)
            return

        writer = AcquiredJobWriter(session)
        projected["status"] = result.outcome.status
        projected["collected"] = len(result.outcome.jobs)
        projected["failed"] = result.outcome.rejection_counts.rejected_items
        written = writer.write(
            run_id=run_id, source_id=source.id, raw_jobs=result.outcome.jobs, acquisition="ats"
        )
        projected["prefiltered"] += written.prefiltered
        projected["new_jobs"] += written.new_jobs
        projected["duplicates"] += written.duplicates
        source.last_success_at = datetime.now(UTC)
        source.last_error_code = None
        self._set_result(run, result.source_id, projected)

    def _record_persistence_failure(self, run_id: str, result: CollectionResult) -> None:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            source = session.get(Source, result.source_id)
            if run is None or source is None:
                raise LookupError("persistence failure could not be recorded")
            source.last_error_at = datetime.now(UTC)
            source.last_error_code = CollectorFailureCode.PERSISTENCE.value
            projection = self._historical_projection(result.outcome)
            projection.update(
                status="failed", failed=1, error_code=CollectorFailureCode.PERSISTENCE.value
            )
            self._set_result(run, result.source_id, projection)
            session.commit()

    @staticmethod
    def _set_result(run: JobSearchRun, source_id: str, value: dict[str, Any]) -> None:
        results = dict(run.source_results_json or {})
        results[source_id] = value
        run.source_results_json = results

    @staticmethod
    def _historical_projection(outcome: CollectionOutcome) -> dict[str, Any]:
        metrics = outcome.metrics
        rejections = outcome.rejection_counts
        result: dict[str, Any] = {
            "status": outcome.status,
            "collected": metrics.accepted_items,
            "new_jobs": 0,
            "duplicates": 0,
            "prefiltered": 0,
            "failed": 0,
            "collection_metrics": {
                "logical_requests": metrics.logical_requests,
                "logical_pages": metrics.logical_pages,
                "wire_attempts": metrics.wire_attempts,
                "retries": metrics.retries,
                "wire_bytes": metrics.wire_bytes,
                "decoded_bytes": metrics.decoded_bytes,
                "provider_items": metrics.provider_items,
                "overflow_probe_items": metrics.overflow_probe_items,
                "accepted_items": metrics.accepted_items,
                "rejected_items": metrics.rejected_items,
                "duplicate_items": metrics.duplicate_items,
                "canonical_batch_bytes": metrics.canonical_batch_bytes,
                "duration_seconds": metrics.duration_seconds,
            },
            "rejection_counts": {
                "invalid_item": rejections.invalid_item,
                "oversized_item": rejections.oversized_item,
                "duplicate_identical": rejections.duplicate_identical,
                "duplicate_conflict": rejections.duplicate_conflict,
            },
            "retryable": outcome.retryable if isinstance(outcome, CollectionFailure) else False,
            "http_status": outcome.http_status if isinstance(outcome, CollectionFailure) else None,
            "stop_code": outcome.stop_code.value if outcome.stop_code else None,
        }
        if isinstance(outcome, CollectionFailure):
            result["error_code"] = outcome.error_code.value
        return result

    @staticmethod
    def _legacy_outcome(jobs: list[Any]) -> CollectionSuccess:
        from role_radar.domain.dto import RawJob

        typed = tuple(job for job in jobs if isinstance(job, RawJob))
        return CollectionSuccess(
            status="ok",
            jobs=typed,
            metrics=CollectionMetrics(
                provider_items=len(typed), accepted_items=len(typed), canonical_batch_bytes=0
            ),
        )

    def _make_collector(self, snapshot: SourceSnapshot) -> JobCollector:
        if self._collector_factory is not None:
            return self._collector_factory(snapshot)
        return create_collector(
            snapshot,
            CollectorContext(
                budget=self._run_budget,
            ),
        )
