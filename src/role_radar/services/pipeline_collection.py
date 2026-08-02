"""Etapa persistente de collection: prepare, execute (async), finalize."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.collectors.protocols import JobCollector, SourceSnapshot
from role_radar.collectors.registry import (
    CollectorContext,
    SourceSnapshotModel,
    create_collector,
    validate_snapshot,
)
from role_radar.config import Settings
from role_radar.db.models import JobSearchRun, Source
from role_radar.dedup.service import DedupService
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus, SourceType
from role_radar.normalization.jobs import normalize_raw_job
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository


@dataclass(frozen=True)
class CollectionResult:
    source_id: str
    jobs: tuple[RawJob, ...] = ()
    error_code: str | None = None


class PipelineCollectionService:
    """No guarda ORM ni session en atributos usados por coroutines async."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        collector_factory: Callable[[SourceSnapshot], JobCollector] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._collector_factory = collector_factory
        self._settings = settings or Settings()

    def prepare(self, run_id: str) -> tuple[SourceSnapshot, ...]:
        """Carga sources, valida config y fija el snapshot antes del primer I/O."""
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
                        .where(Source.enabled.is_(True))
                        .order_by(Source.name, Source.id)
                    )
                )
                snapshots = tuple(
                    SourceSnapshotModel(
                        source_id=source.id,
                        source_type=SourceType(source.type),
                        name=source.name,
                        configuration=dict(source.configuration or {}),
                    ).as_snapshot()
                    for source in sources
                )
            # create_collector validates adapter-specific config without network.
            for snapshot in snapshots:
                validate_snapshot(snapshot)
            run.source_snapshot_json = [
                SourceSnapshotModel(
                    source_id=item.source_id,
                    source_type=SourceType(item.source_type),
                    name=item.name,
                    configuration=item.configuration,
                ).model_dump(mode="json")
                for item in snapshots
            ]
            run.status = JobSearchRunStatus.COLLECTING
            run.started_at = run.started_at or datetime.now(UTC)
            session.commit()
            return snapshots

    async def execute(self, snapshot: SourceSnapshot) -> CollectionResult:
        """I/O externo únicamente con DTOs frozen/scalars."""
        try:
            collector = self._make_collector(snapshot)
            jobs = await collector.collect(snapshot)
            return CollectionResult(snapshot.source_id, tuple(jobs))
        except Exception:
            return CollectionResult(snapshot.source_id, error_code="collection_failed")

    def finalize(self, run_id: str, result: CollectionResult) -> None:
        """Persiste un source completo en una transacción corta."""
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            source = session.get(Source, result.source_id)
            if source is None:
                raise LookupError("source not found")
            if result.error_code is not None:
                source.last_error_at = datetime.now(UTC)
                outcomes = dict(run.source_results_json or {})
                outcomes[result.source_id] = {"status": "failed", "error_code": result.error_code}
                run.source_results_json = outcomes
                session.commit()
                return

            source.last_success_at = datetime.now(UTC)
            jobs = JobRepository(session)
            runs = RunRepository(session)
            dedup = DedupService(jobs)
            source_stats: dict[str, Any] = {
                "status": "ok",
                "collected": len(result.jobs),
                "failed": 0,
            }
            for raw_job in result.jobs:
                try:
                    normalized = normalize_raw_job(raw_job)
                    if not normalized.title or not normalized.description or not (
                        normalized.application_url or normalized.source_url
                    ):
                        source_stats["prefiltered"] = source_stats.get("prefiltered", 0) + 1
                        continue
                    resolved = dedup.resolve(
                        normalized=normalized,
                        source_id=source.id,
                        raw_payload=raw_job.structured_data,
                    )
                    outcome = "new" if resolved.is_new else "existing"
                    for stage in (
                        RunJobStage.COLLECTED,
                        RunJobStage.NORMALIZED,
                        RunJobStage.DEDUPLICATED,
                    ):
                        runs.update_run_job(
                            run_id=run_id,
                            job_id=resolved.job.id,
                            stage=stage,
                            status=RunJobStatus.SUCCEEDED,
                            outcome_json=(
                                {"dedup": outcome}
                                if stage is RunJobStage.DEDUPLICATED
                                else None
                            ),
                        )
                    if resolved.is_new:
                        source_stats["new_jobs"] = source_stats.get("new_jobs", 0) + 1
                    else:
                        source_stats["duplicates"] = source_stats.get("duplicates", 0) + 1
                except Exception:
                    source_stats["failed"] = source_stats.get("failed", 0) + 1
            outcomes = dict(run.source_results_json or {})
            outcomes[result.source_id] = source_stats
            run.source_results_json = outcomes
            session.commit()

    def _make_collector(self, snapshot: SourceSnapshot) -> JobCollector:
        if self._collector_factory is not None:
            return self._collector_factory(snapshot)
        return create_collector(
            snapshot,
            CollectorContext(
                timeout=self._settings.http_timeout_seconds,
                user_agent=self._settings.http_user_agent,
            ),
        )
