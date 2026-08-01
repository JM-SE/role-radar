"""Router de ofertas (GET /jobs, GET /jobs/{id}).

Sin POST /jobs en F1: la escritura de ofertas es excepción F1 (seed/tests),
la hará el worker en fases posteriores (política §11 de la spec).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from role_radar.api.deps import get_job_repository
from role_radar.api.schemas.jobs import JobDetailResponse, JobResponse
from role_radar.domain.enums import JobStatus
from role_radar.repositories.jobs import JobRepository

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=list[JobResponse])
def list_jobs(
    status: JobStatus | None = None,
    company: str | None = None,
    limit: int = 50,
    offset: int = 0,
    *,
    repo: Annotated[JobRepository, Depends(get_job_repository)],
) -> list[JobResponse]:
    """Lista ofertas canónicas con filtros opcionales (status, company, paginación)."""
    jobs = repo.list(status=status, company=company, limit=limit, offset=offset)
    return [JobResponse.model_validate(job) for job in jobs]


@router.get("/{job_id}", response_model=JobDetailResponse)
def get_job(
    job_id: str,
    repo: Annotated[JobRepository, Depends(get_job_repository)],
) -> JobDetailResponse:
    """Detalle de una oferta con sus referencias de fuente (404 si no existe)."""
    job = repo.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobDetailResponse.model_validate(job)
