"""API de intents persistentes; nunca ejecuta el pipeline."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy import select

from role_radar.api.deps import get_run_service
from role_radar.api.schemas.runs import (
    NotificationSummary,
    RunCreateRequest,
    RunJobResponse,
    RunResponse,
)
from role_radar.db.models import JobSearchRun, NotificationBatch, NotificationItem
from role_radar.domain.enums import JobSearchRunStatus
from role_radar.services.run_service import RunConflict, RunNotFound, RunService

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", response_model=RunResponse, status_code=status.HTTP_202_ACCEPTED)
def create_run(
    payload: RunCreateRequest,
    response: Response,
    service: Annotated[RunService, Depends(get_run_service)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> RunResponse:
    try:
        run = service.create(
            reason=payload.reason,
            profile_id=payload.profile_id,
            idempotency_key=idempotency_key,
        )
    except RunNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RunConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.headers["Location"] = f"/runs/{run.id}"
    return _response(run)


@router.get("", response_model=list[RunResponse])
def list_runs(
    service: Annotated[RunService, Depends(get_run_service)],
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status_filter: Annotated[JobSearchRunStatus | None, Query(alias="status")] = None,
    profile_id: str | None = None,
) -> list[RunResponse]:
    runs = service.list(
        limit=limit,
        offset=offset,
        status=status_filter,
        profile_id=profile_id,
    )
    return [_response(run) for run in runs]


@router.get("/{run_id}", response_model=RunResponse)
def get_run(run_id: str, service: Annotated[RunService, Depends(get_run_service)]) -> RunResponse:
    try:
        return _response(service.get(run_id))
    except RunNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{run_id}/retry", response_model=RunResponse, status_code=status.HTTP_202_ACCEPTED)
def retry_run(
    run_id: str,
    response: Response,
    service: Annotated[RunService, Depends(get_run_service)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> RunResponse:
    try:
        run = service.retry(run_id, idempotency_key=idempotency_key)
    except RunNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RunConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.headers["Location"] = f"/runs/{run.id}"
    return _response(run)


def _response(run: JobSearchRun) -> RunResponse:
    # Access only ORM fields explicitly allowed by the public contract.
    jobs = getattr(run, "run_jobs", []) or []
    return RunResponse(
        id=run.id,
        reason=run.reason,
        status=run.status,
        profile_id=run.profile_id,
        retry_of_run_id=run.retry_of_run_id,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
        error_code=run.error_code,
        stats=run.stats_json or {},
        claimed_by=run.claimed_by,
        lease_expires_at=run.lease_expires_at,
        heartbeat_at=run.heartbeat_at,
        recovery_count=run.recovery_count,
        notification_mode=getattr(run.notification_mode, "value", run.notification_mode),
        schedule_slot=run.schedule_slot,
        discovery_mode=getattr(run.discovery_mode, "value", run.discovery_mode),
        notification_summary=_notification_summary(run),
        run_jobs=[
            RunJobResponse(
                id=item.id,
                job_id=item.job_id,
                stage=item.stage,
                status=item.status,
                attempt_count=item.attempt_count,
                error_code=item.error_code,
                started_at=item.started_at,
                completed_at=item.completed_at,
                outcome=item.outcome_json,
            )
            for item in jobs
        ],
    )


def _notification_summary(run: JobSearchRun) -> NotificationSummary | None:
    # The relationship is intentionally not exposed; this compact query is only
    # used by the control-plane mapper and contains no body or recipient data.
    session = object.__getattribute__(run, "_sa_instance_state").session
    mode = getattr(run.notification_mode, "value", run.notification_mode)
    if mode == "none" or session is None:
        return None
    batch = session.scalar(
        select(NotificationBatch)
        .where(NotificationBatch.run_id == run.id)
        .order_by(NotificationBatch.created_at.desc())
        .limit(1)
    )
    if batch is None:
        return NotificationSummary(
            mode=mode,
            slot=run.schedule_slot,
            status=None,
            item_count=0,
            attempts=0,
            sent_at=None,
            counts={},
            error_code=None,
        )
    statuses = list(
        session.scalars(
            select(NotificationItem.status).where(NotificationItem.batch_id == batch.id)
        )
    )
    counts: dict[str, int] = {}
    for status_value in statuses:
        key = getattr(status_value, "value", status_value)
        counts[key] = counts.get(key, 0) + 1
    return NotificationSummary(
        mode=mode,
        slot=run.schedule_slot,
        status=getattr(batch.status, "value", batch.status),
        item_count=batch.item_count,
        attempts=batch.attempt_count,
        sent_at=batch.sent_at,
        counts=counts,
        error_code=batch.error_code,
    )
