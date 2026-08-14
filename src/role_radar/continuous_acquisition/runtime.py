"""Public runtime facade plus sanitized status and recovery operations."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from role_radar.config import Settings
from role_radar.continuous_acquisition.orm import (
    ContinuousAcquisitionRun,
    SourceDiscoveryRun,
)
from role_radar.continuous_acquisition.recovery import RecoveryService
from role_radar.continuous_acquisition.runtime_acquisition import run_acquisition_once
from role_radar.continuous_acquisition.runtime_discovery import run_discovery_once
from role_radar.continuous_acquisition.runtime_support import (
    EXIT_CLAIM,
    EXIT_CONFIGURATION,
    EXIT_FAILED,
    EXIT_INDETERMINATE,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_PRECONDITION,
    RuntimeCompositionError,
    RuntimeResult,
    load_runtime_config,
    open_runtime,
    provider_summary,
    require_mode_authorization,
)
from role_radar.continuous_acquisition.runtime_support import (
    LIVE_ACKNOWLEDGEMENT as _LIVE_ACKNOWLEDGEMENT,
)

LIVE_ACKNOWLEDGEMENT = _LIVE_ACKNOWLEDGEMENT
__all__ = (
    "EXIT_CLAIM",
    "EXIT_CONFIGURATION",
    "EXIT_FAILED",
    "EXIT_INDETERMINATE",
    "EXIT_INTERNAL",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "EXIT_PRECONDITION",
    "LIVE_ACKNOWLEDGEMENT",
    "RuntimeCompositionError",
    "RuntimeResult",
    "load_runtime_config",
    "open_runtime",
    "provider_summary",
    "recover",
    "require_mode_authorization",
    "run_acquisition_once",
    "run_discovery_once",
    "status",
)


def status(settings: Settings, *, workflow: str) -> RuntimeResult:
    engine, session = open_runtime(settings)
    try:
        if workflow == "discovery":
            row: Any = session.scalar(
                select(SourceDiscoveryRun).order_by(SourceDiscoveryRun.created_at.desc()).limit(1)
            )
        else:
            row = session.scalar(
                select(ContinuousAcquisitionRun)
                .order_by(ContinuousAcquisitionRun.created_at.desc())
                .limit(1)
            )
        payload: dict[str, Any] = {
            "schema_version": "continuous-status-v1",
            "workflow": workflow,
            "state": row.state if row is not None else "never_run",
        }
        if row is not None:
            payload.update({"run_id": row.id, "slot_key": row.slot_key})
            if workflow == "acquisition":
                payload["counters"] = {
                    "observed": row.observed_count,
                    "created": row.created_count,
                    "duplicate": row.duplicate_count,
                    "stale": row.stale_count,
                    "invalid": row.invalid_count,
                    "conflict": row.conflict_count,
                }
            else:
                payload["registrations"] = row.registered_count
                payload["verified"] = row.verified_count
        return RuntimeResult(payload, EXIT_OK)
    except Exception as exc:
        raise RuntimeCompositionError("status_unavailable", exit_code=EXIT_INTERNAL) from exc
    finally:
        session.close()
        engine.dispose()


def recover(settings: Settings) -> RuntimeResult:
    engine, session = open_runtime(settings)
    try:
        recovered = RecoveryService(session).recover_expired()
        return RuntimeResult(
            {"schema_version": "continuous-recovery-v1", "recovered": recovered}, EXIT_OK
        )
    except Exception as exc:
        session.rollback()
        raise RuntimeCompositionError("recovery_unavailable", exit_code=EXIT_INTERNAL) from exc
    finally:
        session.close()
        engine.dispose()
