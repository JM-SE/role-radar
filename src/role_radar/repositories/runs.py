"""Persistencia de ejecuciones del pipeline (JobSearchRun / RunJob).

Solo I/O: sin máquinas de estado (el worker las manejará en fases posteriores).
Sin API pública de runs en F1 (D15): usado por seed y tests.
"""


from sqlalchemy.orm import Session

from role_radar.db.models import JobSearchRun, RunJob
from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus


class RunRepository:
    """I/O de JobSearchRun y RunJob. Sin reglas de negocio ni commit propio."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_run(
        self,
        reason: str,
        status: JobSearchRunStatus = JobSearchRunStatus.PENDING,
    ) -> JobSearchRun:
        run = JobSearchRun(reason=reason, status=status)
        self._session.add(run)
        self._session.flush()
        return run

    def get_run(self, run_id: str) -> JobSearchRun | None:
        return self._session.get(JobSearchRun, run_id)

    def add_run_job(
        self,
        *,
        run_id: str,
        job_id: str,
        stage: RunJobStage,
        status: RunJobStatus = RunJobStatus.PENDING,
        error_message: str | None = None,
    ) -> RunJob:
        run_job = RunJob(
            run_id=run_id,
            job_id=job_id,
            stage=stage,
            status=status,
            error_message=error_message,
        )
        self._session.add(run_job)
        self._session.flush()
        return run_job
