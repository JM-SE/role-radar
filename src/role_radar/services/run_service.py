"""Casos de uso de control-plane para crear y consultar runs."""

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import JobSearchRun
from role_radar.domain.enums import JobSearchRunStatus
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository


class RunServiceError(ValueError):
    pass


class RunConflict(RunServiceError):
    pass


class RunNotFound(RunServiceError):
    pass


@dataclass(frozen=True)
class RunIntent:
    reason: str
    profile_id: str
    request_hash: str


class RunService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._runs = RunRepository(session)
        self._profiles = ProfileRepository(session)

    def create(
        self,
        *,
        reason: str = "manual",
        profile_id: str | None = None,
        idempotency_key: str | None = None,
        trigger_namespace: str = "POST:/runs",
        notification_mode: str = "none",
        schedule_slot: str | None = None,
    ) -> JobSearchRun:
        intent = self._resolve_intent(reason=reason, profile_id=profile_id)
        trigger_hash = (
            _hash(f"{trigger_namespace}:{_normalize_key(idempotency_key)}")
            if idempotency_key
            else None
        )
        if trigger_hash is not None:
            existing = self._runs.find_by_trigger_hash(trigger_hash)
            if existing is not None:
                if existing.request_hash != intent.request_hash:
                    raise RunConflict("idempotency key was used with a different request")
                return existing
        try:
            with self._session.begin_nested():
                return self._runs.create_run(
                    intent.reason,
                    profile_id=intent.profile_id,
                    trigger_key_hash=trigger_hash,
                    request_hash=intent.request_hash,
                    notification_mode=notification_mode,
                    schedule_slot=schedule_slot,
                )
        except IntegrityError as exc:
            if trigger_hash is None:
                raise
            existing = self._runs.find_by_trigger_hash(trigger_hash)
            if existing is None or existing.request_hash != intent.request_hash:
                raise RunConflict("idempotency key was used with a different request") from exc
            return existing

    def resolve_profile_id(self, profile_id: str | None = None) -> str:
        """Resolve the profile that a new intent would freeze."""
        if profile_id is not None:
            if self._profiles.get(profile_id) is None:
                raise RunNotFound("profile not found")
            return profile_id
        active = self._profiles.list_active()
        if len(active) != 1:
            raise RunConflict("profile_id is required unless exactly one active profile exists")
        return active[0].id

    def list(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        status: JobSearchRunStatus | None = None,
        profile_id: str | None = None,
    ) -> list[JobSearchRun]:
        return self._runs.list_runs(
            limit=limit, offset=offset, status=status, profile_id=profile_id
        )

    def get(self, run_id: str) -> JobSearchRun:
        run = self._runs.get_run_with_jobs(run_id)
        if run is None:
            raise RunNotFound("run not found")
        return run

    def retry(self, run_id: str, *, idempotency_key: str | None = None) -> JobSearchRun:
        parent = self._runs.get_run(run_id)
        if parent is None:
            raise RunNotFound("run not found")
        if parent.status not in {
            JobSearchRunStatus.COMPLETED,
            JobSearchRunStatus.FAILED,
            JobSearchRunStatus.CANCELLED,
        }:
            raise RunConflict("only terminal runs can be retried")
        trigger_hash = (
            _hash(f"POST:/runs/{run_id}/retry:{_normalize_key(idempotency_key)}")
            if idempotency_key
            else None
        )
        if trigger_hash:
            existing = self._runs.find_by_trigger_hash(trigger_hash)
            if existing is not None:
                return existing
        try:
            with self._session.begin_nested():
                return self._runs.create_run(
                    parent.reason,
                    profile_id=parent.profile_id,
                    retry_of_run_id=parent.id,
                    trigger_key_hash=trigger_hash,
                    request_hash=parent.request_hash,
                    source_snapshot_json=parent.source_snapshot_json,
                    notification_mode=getattr(
                        parent.notification_mode, "value", parent.notification_mode
                    ),
                    schedule_slot=parent.schedule_slot,
                )
        except IntegrityError as exc:
            if trigger_hash is None:
                raise
            existing = self._runs.find_by_trigger_hash(trigger_hash)
            if existing is None:
                raise RunConflict("retry idempotency conflict") from exc
            return existing

    def _resolve_intent(self, *, reason: str, profile_id: str | None) -> RunIntent:
        normalized_reason = " ".join(reason.split())[:255]
        if not normalized_reason:
            raise RunConflict("reason must not be empty")
        if profile_id is not None:
            profile = self._profiles.get(profile_id)
            if profile is None:
                raise RunNotFound("profile not found")
        else:
            active = self._profiles.list_active()
            if len(active) != 1:
                raise RunConflict("profile_id is required unless exactly one active profile exists")
            profile = active[0]
        request_hash = _hash(
            json.dumps(
                {"reason": normalized_reason, "profile_id": profile.id},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return RunIntent(normalized_reason, profile.id, request_hash)


def _normalize_key(value: str | None) -> str:
    if value is None:
        return ""
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 255:
        raise RunConflict("invalid idempotency key")
    return normalized


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
