"""Orquestación del primer pipeline de adquisición."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.protocols import CollectionContext, JobCollector
from role_radar.config import Settings
from role_radar.db.models import JobSearchRun, Source
from role_radar.dedup.service import DedupService
from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus, SourceType
from role_radar.logging import get_logger
from role_radar.normalization.jobs import normalize_raw_job
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository


class CollectionService:
    """Coordina collector async y persistencia sync; nunca hace commit."""

    def __init__(
        self,
        session: Session,
        *,
        sources: SourceRepository | None = None,
        jobs: JobRepository | None = None,
        runs: RunRepository | None = None,
        collector: JobCollector | None = None,
    ) -> None:
        self._session = session
        self._sources = sources or SourceRepository(session)
        self._jobs = jobs or JobRepository(session)
        self._runs = runs or RunRepository(session)
        if collector is None:
            settings = Settings()
            collector = GreenhouseCollector(
                timeout=settings.http_timeout_seconds,
                user_agent=settings.http_user_agent,
            )
        self._collector = collector
        self._logger = get_logger()

    async def run_collect(self, *, reason: str = "cli_collect") -> JobSearchRun:
        run = self._runs.create_run(reason=reason, status=JobSearchRunStatus.PENDING)
        started_at = datetime.now(UTC)
        self._runs.update_run_status(
            run.id, JobSearchRunStatus.COLLECTING, started_at=started_at
        )
        sources = self._sources.list_enabled(SourceType.GREENHOUSE)
        stats: dict[str, int] = {
            "collected": 0,
            "new_jobs": 0,
            "duplicates": 0,
            "prefiltered": 0,
            "failed": 0,
            "sources_ok": 0,
            "sources_failed": 0,
        }
        if not sources:
            self._runs.update_run_status(
                run.id,
                JobSearchRunStatus.FAILED,
                error_message="no enabled greenhouse sources",
                stats_json=stats,
                completed_at=datetime.now(UTC),
            )
            return run

        raw_by_source: list[tuple[Source, Any]] = []
        for source in sources:
            configuration = source.configuration or {}
            board_token = configuration.get("board_token")
            if not isinstance(board_token, str) or not board_token.strip():
                stats["sources_failed"] += 1
                self._sources.update_last_error(source.id)
                self._logger.warning(
                    "greenhouse_board_missing_token", source_id=source.id, source_name=source.name
                )
                continue
            context = CollectionContext(
                source_id=source.id,
                board_token=board_token,
                company=configuration.get("company") or source.name,
                source_name=source.name,
            )
            try:
                raw_jobs = await self._collector.collect(context)
            except Exception as exc:
                stats["sources_failed"] += 1
                self._sources.update_last_error(source.id)
                self._logger.error(
                    "greenhouse_board_collection_failed",
                    source_id=source.id,
                    source_name=source.name,
                    error=str(exc),
                )
                continue
            stats["sources_ok"] += 1
            stats["collected"] += len(raw_jobs)
            self._sources.update_last_success(source.id)
            raw_by_source.extend((source, raw_job) for raw_job in raw_jobs)

        self._runs.update_run_status(run.id, JobSearchRunStatus.NORMALIZING)
        dedup = DedupService(self._jobs)
        recorded_stages: set[tuple[str, RunJobStage]] = set()
        for source, raw_job in raw_by_source:
            try:
                normalized = normalize_raw_job(raw_job)
                if not normalized.title or not normalized.description or not (
                    normalized.application_url or normalized.source_url
                ):
                    stats["prefiltered"] += 1
                    continue
                result = dedup.resolve(
                    normalized=normalized,
                    source_id=source.id,
                    raw_payload=raw_job.structured_data,
                )
                if result.is_new:
                    stats["new_jobs"] += 1
                else:
                    stats["duplicates"] += 1
                for stage in (
                    RunJobStage.COLLECTED,
                    RunJobStage.NORMALIZED,
                    RunJobStage.DEDUPLICATED,
                ):
                    key = (result.job.id, stage)
                    if key not in recorded_stages:
                        self._runs.add_run_job(
                            run_id=run.id,
                            job_id=result.job.id,
                            stage=stage,
                            status=RunJobStatus.SUCCEEDED,
                        )
                        recorded_stages.add(key)
            except Exception as exc:
                stats["failed"] += 1
                self._logger.error("job_processing_failed", error=str(exc))

        all_sources_failed = stats["sources_ok"] == 0
        final_status = (
            JobSearchRunStatus.FAILED
            if all_sources_failed
            else JobSearchRunStatus.COMPLETED
        )
        self._runs.update_run_status(
            run.id,
            final_status,
            error_message="all enabled greenhouse sources failed" if all_sources_failed else None,
            stats_json=stats,
            completed_at=datetime.now(UTC),
        )
        return run
