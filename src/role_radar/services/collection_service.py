"""Orquestación del primer pipeline de adquisición."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from role_radar.collectors.protocols import SourceSnapshot
from role_radar.db.models import JobSearchRun
from role_radar.db.session import get_session_factory
from role_radar.domain.enums import JobSearchRunStatus
from role_radar.logging import get_logger
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.pipeline_collection import CollectionResult, PipelineCollectionService


class CollectionService:
    """Coordina collector async y persistencia sync; nunca hace commit."""

    def __init__(
        self,
        session: Session,
        *,
        sources: SourceRepository | None = None,
        jobs: JobRepository | None = None,
        runs: RunRepository | None = None,
        collector: Any = None,
    ) -> None:
        self._session = session
        self._sources = sources or SourceRepository(session)
        self._jobs = jobs or JobRepository(session)
        self._runs = runs or RunRepository(session)
        self._collector = collector
        self._logger = get_logger()

    def prepare(self, run_id: str) -> tuple[SourceSnapshot, ...]:
        """Nueva frontera F5: materializa snapshots sin hacer I/O externo."""
        service = PipelineCollectionService(
            self._session_factory(),
            collector_factory=(lambda _snapshot: self._collector)
            if self._collector is not None
            else None,
        )
        return service.prepare(run_id)

    async def execute(self, snapshot: SourceSnapshot) -> CollectionResult:
        """Execute solo recibe un snapshot DTO; no usa Session/ORM."""
        service = PipelineCollectionService(
            self._session_factory(),
            collector_factory=(lambda _snapshot: self._collector)
            if self._collector is not None
            else None,
        )
        return await service.execute(snapshot)

    def finalize(self, run_id: str, result: CollectionResult) -> None:
        """Finaliza en una sesión nueva y corta."""
        self._persistent_service().finalize(run_id, result)

    def _session_factory(self) -> Any:
        bind = self._session.get_bind()
        if not isinstance(bind, Engine):
            raise TypeError("persistent collection requires an Engine bind")
        return get_session_factory(bind)

    def _persistent_service(self) -> PipelineCollectionService:
        return PipelineCollectionService(
            self._session_factory(),
            collector_factory=(lambda _snapshot: self._collector)
            if self._collector is not None
            else None,
        )

    async def run_collect(self, *, reason: str = "cli_collect") -> JobSearchRun:
        run = self._runs.create_run(reason=reason, status=JobSearchRunStatus.PENDING)
        run_id = run.id
        self._session.flush()
        self._session.commit()
        # Only the scalar run id crosses the async boundary. The persistent
        # pipeline owns short-lived sessions for prepare/finalize.
        pipeline = PipelineCollectionService(
            self._session_factory(),
            collector_factory=(lambda _snapshot: self._collector)
            if self._collector is not None
            else None,
        )
        snapshots = pipeline.prepare(run_id)
        stats: dict[str, int] = {
            "collected": 0,
            "new_jobs": 0,
            "duplicates": 0,
            "prefiltered": 0,
            "failed": 0,
            "sources_ok": 0,
            "sources_failed": 0,
        }
        if not snapshots:
            self._runs.update_run_status(
                run_id,
                JobSearchRunStatus.FAILED,
                error_message="no enabled sources",
                stats_json=stats,
                completed_at=datetime.now(UTC),
            )
            self._session.commit()
            return self._session.get(JobSearchRun, run_id) or run

        results: list[CollectionResult] = []
        for snapshot in snapshots:
            results.append(await pipeline.execute(snapshot))
        for result in results:
            pipeline.finalize(run_id, result)

        persisted = self._session.get(JobSearchRun, run_id)
        if persisted is not None:
            self._session.refresh(persisted)
        outcomes = (persisted.source_results_json if persisted else None) or {}
        for outcome in outcomes.values():
            if outcome.get("status") == "failed":
                stats["sources_failed"] += 1
            else:
                stats["sources_ok"] += 1
                stats["collected"] += int(outcome.get("collected", 0))
                stats["new_jobs"] += int(outcome.get("new_jobs", 0))
                stats["duplicates"] += int(outcome.get("duplicates", 0))
                stats["prefiltered"] += int(outcome.get("prefiltered", 0))
                stats["failed"] += int(outcome.get("failed", 0))

        all_sources_failed = stats["sources_ok"] == 0
        final_status = (
            JobSearchRunStatus.FAILED if all_sources_failed else JobSearchRunStatus.COMPLETED
        )
        self._runs.update_run_status(
            run_id,
            final_status,
            error_message="all enabled greenhouse sources failed" if all_sources_failed else None,
            stats_json=stats,
            completed_at=datetime.now(UTC),
        )
        self._session.commit()
        return self._session.get(JobSearchRun, run_id) or run
