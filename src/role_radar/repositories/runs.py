"""Persistencia de intents, leases y transiciones de ``JobSearchRun``."""

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session, selectinload

from role_radar.db.models import JobSearchRun, RunJob
from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus

_TERMINAL = {
    JobSearchRunStatus.COMPLETED,
    JobSearchRunStatus.FAILED,
    JobSearchRunStatus.CANCELLED,
}
_RECOVERABLE = {
    JobSearchRunStatus.COLLECTING,
    JobSearchRunStatus.NORMALIZING,
    JobSearchRunStatus.EXTRACTING,
    JobSearchRunStatus.SCORING,
    JobSearchRunStatus.DEEP_EVALUATING,
    JobSearchRunStatus.NOTIFYING,
}


class RunAlreadyTerminalError(ValueError):
    """No se puede mutar un run terminal."""


class RunRepository:
    """Gateway sync; el caller decide los límites transaccionales."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_run(
        self,
        reason: str,
        status: JobSearchRunStatus = JobSearchRunStatus.PENDING,
        *,
        profile_id: str | None = None,
        retry_of_run_id: str | None = None,
        trigger_key_hash: str | None = None,
        request_hash: str = "",
        source_snapshot_json: list[dict[str, Any]] | None = None,
    ) -> JobSearchRun:
        run = JobSearchRun(
            reason=reason,
            status=status,
            profile_id=profile_id,
            retry_of_run_id=retry_of_run_id,
            trigger_key_hash=trigger_key_hash,
            request_hash=request_hash,
            source_snapshot_json=source_snapshot_json,
            recovery_count=0,
        )
        self._session.add(run)
        self._session.flush()
        return run

    def get_run(self, run_id: str) -> JobSearchRun | None:
        return self._session.get(JobSearchRun, run_id)

    def get_run_with_jobs(self, run_id: str) -> JobSearchRun | None:
        stmt = (
            select(JobSearchRun)
            .where(JobSearchRun.id == run_id)
            .options(selectinload(JobSearchRun.run_jobs))
        )
        return self._session.scalars(stmt).first()

    def find_by_trigger_hash(self, trigger_key_hash: str) -> JobSearchRun | None:
        return self._session.scalar(
            select(JobSearchRun).where(JobSearchRun.trigger_key_hash == trigger_key_hash)
        )

    def list_runs(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: JobSearchRunStatus | None = None,
        profile_id: str | None = None,
    ) -> list[JobSearchRun]:
        stmt = select(JobSearchRun).order_by(JobSearchRun.created_at.desc(), JobSearchRun.id.asc())
        if status is not None:
            stmt = stmt.where(JobSearchRun.status == status)
        if profile_id is not None:
            stmt = stmt.where(JobSearchRun.profile_id == profile_id)
        return list(self._session.scalars(stmt.limit(limit).offset(offset)))

    def update_run_status(
        self,
        run_id: str,
        status: JobSearchRunStatus,
        *,
        error_message: str | None = None,
        error_code: str | None = None,
        stats_json: dict[str, Any] | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> JobSearchRun | None:
        run = self._session.get(JobSearchRun, run_id)
        if run is None:
            return None
        if run.status in _TERMINAL:
            raise RunAlreadyTerminalError("run is terminal")
        run.status = status
        if error_message is not None:
            run.error_message = error_message[:512]
        if error_code is not None:
            run.error_code = _safe_code(error_code)
        if stats_json is not None:
            run.stats_json = stats_json
        if started_at is not None:
            run.started_at = started_at
        if completed_at is not None:
            run.completed_at = completed_at
        self._session.flush()
        return run

    def set_source_snapshot(
        self, run_id: str, snapshot: list[dict[str, Any]]
    ) -> JobSearchRun | None:
        run = self._session.get(JobSearchRun, run_id)
        if run is None:
            return None
        if run.source_snapshot_json is None:
            run.source_snapshot_json = snapshot
            self._session.flush()
        return run

    def set_source_result(self, run_id: str, source_id: str, result: dict[str, Any]) -> None:
        run = self._session.get(JobSearchRun, run_id)
        if run is None:
            raise LookupError("run not found")
        outcomes = dict(run.source_results_json or {})
        outcomes[source_id] = result
        run.source_results_json = outcomes
        self._session.flush()

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_duration_seconds: float = 600.0,
        now: datetime | None = None,
        max_recoveries: int = 5,
    ) -> JobSearchRun | None:
        """Claim CAS de un único run, sin mantener la sesión durante I/O."""
        current = now or datetime.now(UTC)
        expiry = current + timedelta(seconds=lease_duration_seconds)
        stale = or_(
            JobSearchRun.lease_expires_at.is_(None),
            JobSearchRun.lease_expires_at <= current,
        )
        active = and_(
            JobSearchRun.status.in_(tuple(_RECOVERABLE)),
            stale,
            JobSearchRun.recovery_count < max_recoveries,
        )
        pending = and_(JobSearchRun.status == JobSearchRunStatus.PENDING, stale)
        candidate = self._session.scalar(
            select(JobSearchRun)
            .where(or_(active, pending))
            .order_by(JobSearchRun.created_at.asc(), JobSearchRun.id.asc())
            .limit(1)
        )
        if candidate is None:
            exhausted = self._session.scalar(
                select(JobSearchRun)
                .where(
                    JobSearchRun.status.in_(tuple(_RECOVERABLE)),
                    stale,
                    JobSearchRun.recovery_count >= max_recoveries,
                )
                .order_by(JobSearchRun.created_at.asc(), JobSearchRun.id.asc())
                .limit(1)
            )
            if exhausted is not None:
                exhausted.status = JobSearchRunStatus.FAILED
                exhausted.error_code = "recovery_budget_exhausted"
                exhausted.completed_at = current
                exhausted.claimed_by = None
                exhausted.lease_expires_at = None
                self._session.flush()
            return None
        was_recovery = candidate.status in _RECOVERABLE
        condition = and_(JobSearchRun.id == candidate.id, stale)
        if was_recovery:
            condition = and_(
                condition,
                JobSearchRun.status.in_(tuple(_RECOVERABLE)),
                JobSearchRun.recovery_count < max_recoveries,
            )
        else:
            condition = and_(condition, JobSearchRun.status == JobSearchRunStatus.PENDING)
        result = self._session.execute(
            update(JobSearchRun)
            .where(condition)
            .values(
                claimed_by=worker_id,
                lease_expires_at=expiry,
                heartbeat_at=current,
                recovery_count=JobSearchRun.recovery_count + (1 if was_recovery else 0),
                updated_at=current,
            )
        )
        if int(cast(Any, result).rowcount) != 1:
            self._session.rollback()
            return None
        self._session.flush()
        return self._session.get(JobSearchRun, candidate.id)

    def heartbeat(
        self,
        run_id: str,
        *,
        worker_id: str,
        lease_duration_seconds: float = 600.0,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(UTC)
        result = self._session.execute(
            update(JobSearchRun)
            .where(
                JobSearchRun.id == run_id,
                JobSearchRun.claimed_by == worker_id,
                JobSearchRun.status.not_in(tuple(_TERMINAL)),
            )
            .values(
                heartbeat_at=current,
                lease_expires_at=current + timedelta(seconds=lease_duration_seconds),
                updated_at=current,
            )
        )
        self._session.flush()
        return int(cast(Any, result).rowcount) == 1

    def release(self, run_id: str, *, worker_id: str) -> bool:
        result = self._session.execute(
            update(JobSearchRun)
            .where(JobSearchRun.id == run_id, JobSearchRun.claimed_by == worker_id)
            .values(claimed_by=None, lease_expires_at=None, heartbeat_at=None)
        )
        self._session.flush()
        return int(cast(Any, result).rowcount) == 1

    def add_run_job(
        self,
        *,
        run_id: str,
        job_id: str,
        stage: RunJobStage,
        status: RunJobStatus = RunJobStatus.PENDING,
        error_message: str | None = None,
        error_code: str | None = None,
        outcome_json: dict[str, Any] | None = None,
    ) -> RunJob:
        run_job = RunJob(
            run_id=run_id,
            job_id=job_id,
            stage=stage,
            status=status,
            error_message=error_message,
            error_code=_safe_code(error_code) if error_code else None,
            outcome_json=outcome_json,
            attempt_count=1 if status != RunJobStatus.PENDING else 0,
        )
        self._session.add(run_job)
        self._session.flush()
        return run_job

    def get_run_job(self, *, run_id: str, job_id: str, stage: RunJobStage) -> RunJob | None:
        stmt = select(RunJob).where(
            RunJob.run_id == run_id, RunJob.job_id == job_id, RunJob.stage == stage
        )
        return self._session.scalars(stmt).first()

    def update_run_job(
        self,
        *,
        run_id: str,
        job_id: str,
        stage: RunJobStage,
        status: RunJobStatus,
        error_message: str | None = None,
        error_code: str | None = None,
        outcome_json: dict[str, Any] | None = None,
    ) -> RunJob:
        run_job = self.get_run_job(run_id=run_id, job_id=job_id, stage=stage)
        if run_job is None:
            return self.add_run_job(
                run_id=run_id,
                job_id=job_id,
                stage=stage,
                status=status,
                error_message=error_message,
                error_code=error_code,
                outcome_json=outcome_json,
            )
        if run_job.status in {
            RunJobStatus.SUCCEEDED,
            RunJobStatus.FAILED,
            RunJobStatus.SKIPPED,
        }:
            return run_job
        run_job.status = status
        run_job.error_message = error_message[:512] if error_message else None
        run_job.error_code = _safe_code(error_code) if error_code else run_job.error_code
        if outcome_json is not None:
            run_job.outcome_json = outcome_json
        if status in {RunJobStatus.SUCCEEDED, RunJobStatus.FAILED, RunJobStatus.SKIPPED}:
            run_job.completed_at = datetime.now(UTC)
        self._session.flush()
        return run_job


def _safe_code(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._:-" else "_" for char in value)[:128]
