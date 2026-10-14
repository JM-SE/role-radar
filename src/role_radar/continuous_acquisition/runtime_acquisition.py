"""Blocked legacy acquisition entrypoint; the profile-first worker owns writes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from role_radar.config import Settings
from role_radar.continuous_acquisition.contracts import AcquisitionRunResult
from role_radar.continuous_acquisition.providers import BoundedCollectorProvider
from role_radar.continuous_acquisition.runtime_support import (
    EXIT_CLAIM,
    RuntimeCompositionError,
    RuntimeResult,
)


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
    del session, settings, now, owner, canary_id, collector
    raise RuntimeCompositionError("profile_first_worker_required", exit_code=EXIT_CLAIM)
