"""Acquisition composition root for one daily 0..N run."""

from __future__ import annotations

from datetime import datetime
from typing import Any, cast

from sqlalchemy.orm import Session

from role_radar.config import Settings
from role_radar.continuous_acquisition.acquisition import AcquisitionService
from role_radar.continuous_acquisition.contracts import (
    ACQUISITION_POLICY_VERSION,
    AcquisitionRunResult,
)
from role_radar.continuous_acquisition.providers import (
    BoundedCollectorProvider,
    create_bounded_collector_provider,
)
from role_radar.continuous_acquisition.repositories import (
    FenceLostError,
    LeaseOwnedError,
    RunRepository,
    SourceSnapshotRepository,
)
from role_radar.continuous_acquisition.runtime_support import (
    EXIT_CLAIM,
    RuntimeCompositionError,
    RuntimeResult,
    as_utc,
    owner_for,
    state_exit_code,
)
from role_radar.continuous_acquisition.scheduling import acquisition_slot


def _payload(result: AcquisitionRunResult, *, run_id: str, slot_key: str) -> dict[str, Any]:
    return {
        "schema_version": "continuous-acquisition-result-v1",
        "workflow": "acquisition",
        "run_id": run_id,
        "slot_key": slot_key,
        "state": result.state.value,
        "new_jobs": result.new_jobs,
        "counters": {
            "observed": result.counters.observed,
            "created": result.counters.created,
            "duplicate": result.counters.duplicate,
            "stale": result.counters.stale,
            "invalid": result.counters.invalid,
            "conflict": result.counters.conflict,
        },
        "outcomes": [
            {
                "source_id": outcome.source_id,
                "state": outcome.state.value,
                "usable": outcome.usable,
                "error_code": outcome.error_code,
                "counters": {
                    "observed": outcome.counters.observed,
                    "created": outcome.counters.created,
                    "duplicate": outcome.counters.duplicate,
                    "stale": outcome.counters.stale,
                    "invalid": outcome.counters.invalid,
                    "conflict": outcome.counters.conflict,
                },
            }
            for outcome in result.outcomes
        ],
        "terminal_code": result.terminal_code,
    }


def run_acquisition_once(
    session: Session,
    *,
    settings: Settings,
    now: datetime | None = None,
    owner: str | None = None,
    canary_id: str | None = None,
    collector: BoundedCollectorProvider | None = None,
) -> RuntimeResult:
    as_of = as_utc(now)
    snapshots = SourceSnapshotRepository(session).enabled_ats_snapshot()
    slot_key = acquisition_slot(as_of, canary_id=canary_id)
    worker = owner_for(settings, owner)
    repository = RunRepository(session)
    try:
        run = repository.claim_acquisition(
            slot_key=slot_key,
            policy_version=ACQUISITION_POLICY_VERSION,
            snapshots=snapshots,
            owner=worker,
        )
        session.commit()
    except LeaseOwnedError as exc:
        session.rollback()
        raise RuntimeCompositionError("lease_owned", exit_code=EXIT_CLAIM) from exc
    except ValueError as exc:
        session.rollback()
        raise RuntimeCompositionError(
            getattr(exc, "code", "claim_conflict"), exit_code=EXIT_CLAIM
        ) from exc

    if run.state not in {"planned", "running"}:
        payload = {
            "schema_version": "continuous-acquisition-result-v1",
            "workflow": "acquisition",
            "run_id": run.id,
            "slot_key": slot_key,
            "state": run.state,
            "new_jobs": run.created_count,
            "replay": True,
        }
        return RuntimeResult(payload, state_exit_code(run.state))

    bounded = collector or create_bounded_collector_provider()
    service = AcquisitionService(
        run_repository=repository,
        snapshots=snapshots,
        collectors=cast(Any, {"greenhouse": bounded, "lever": bounded}),
        as_of_utc=as_of,
        owner=worker,
    )
    try:
        result = service.run(slot_key=slot_key)
    except FenceLostError as exc:
        session.rollback()
        raise RuntimeCompositionError("fence_lost", exit_code=EXIT_CLAIM) from exc
    return RuntimeResult(
        _payload(result, run_id=run.id, slot_key=slot_key), state_exit_code(result.state.value)
    )
