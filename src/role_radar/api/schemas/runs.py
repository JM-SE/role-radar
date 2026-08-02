"""Contratos públicos del control-plane de runs."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus


class RunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str = Field(default="manual", min_length=1, max_length=255)
    profile_id: str | None = None


class RunJobResponse(BaseModel):
    id: str
    job_id: str
    stage: RunJobStage
    status: RunJobStatus
    attempt_count: int
    error_code: str | None
    started_at: datetime | None
    completed_at: datetime | None
    outcome: dict[str, Any] | None = None


class RunResponse(BaseModel):
    id: str
    reason: str
    status: JobSearchRunStatus
    profile_id: str | None
    retry_of_run_id: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    error_code: str | None
    stats: dict[str, int]
    claimed_by: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    recovery_count: int
    run_jobs: list[RunJobResponse]
