"""Journal de checkpoints por oferta y etapa."""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import RunJob
from role_radar.domain.enums import RunJobStage, RunJobStatus


class RunJobRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, *, run_id: str, job_id: str, stage: RunJobStage) -> RunJob | None:
        return self._session.scalar(
            select(RunJob).where(
                RunJob.run_id == run_id, RunJob.job_id == job_id, RunJob.stage == stage
            )
        )

    def list_for_run(self, run_id: str) -> list[RunJob]:
        return list(
            self._session.scalars(
                select(RunJob).where(RunJob.run_id == run_id).order_by(RunJob.created_at, RunJob.id)
            )
        )

    def claim_attempt(
        self,
        *,
        run_id: str,
        job_id: str,
        stage: RunJobStage,
        max_attempts: int,
        now: datetime | None = None,
    ) -> RunJob | None:
        row = self.get(run_id=run_id, job_id=job_id, stage=stage)
        if row is None:
            row = RunJob(run_id=run_id, job_id=job_id, stage=stage)
            self._session.add(row)
            self._session.flush()
        if row.status in {RunJobStatus.SUCCEEDED, RunJobStatus.SKIPPED}:
            return None
        if row.status == RunJobStatus.FAILED and row.attempt_count >= max_attempts:
            return None
        current = now or datetime.now(UTC)
        if row.next_attempt_at is not None and row.next_attempt_at > current:
            return None
        row.status = RunJobStatus.IN_PROGRESS
        row.attempt_count += 1
        row.started_at = current
        row.next_attempt_at = None
        self._session.flush()
        return row

    def defer_retry(
        self,
        row: RunJob,
        *,
        error_code: str,
        delay_seconds: float,
        now: datetime | None = None,
    ) -> RunJob:
        row.status = RunJobStatus.PENDING
        row.error_code = error_code[:128]
        row.next_attempt_at = (now or datetime.now(UTC)) + timedelta(seconds=delay_seconds)
        self._session.flush()
        return row

    def finish(
        self,
        row: RunJob,
        *,
        status: RunJobStatus,
        outcome: dict[str, Any] | None = None,
        error_code: str | None = None,
    ) -> RunJob:
        if row.status in {RunJobStatus.SUCCEEDED, RunJobStatus.FAILED, RunJobStatus.SKIPPED}:
            return row
        row.status = status
        row.completed_at = datetime.now(UTC)
        row.error_code = error_code[:128] if error_code else row.error_code
        row.outcome_json = outcome if outcome is not None else row.outcome_json
        self._session.flush()
        return row
