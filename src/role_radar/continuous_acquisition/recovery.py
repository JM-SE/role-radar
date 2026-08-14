"""Conservative lease recovery: unknown transmissions are indeterminate."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from role_radar.continuous_acquisition.orm import (
    ContinuousAcquisitionRun,
    ContinuousAcquisitionSourceOperation,
    SourceDiscoveryOperation,
    SourceDiscoveryRun,
)


class RecoveryService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def recover_expired(self, *, now: datetime | None = None) -> int:
        current = now or datetime.now(UTC)
        runs = list(self.session.scalars(select(ContinuousAcquisitionRun).where(ContinuousAcquisitionRun.lease_expires_at.is_not(None), ContinuousAcquisitionRun.lease_expires_at < current, ContinuousAcquisitionRun.state.in_(("planned", "running")))))
        for run in runs:
            self.session.execute(update(ContinuousAcquisitionSourceOperation).where(ContinuousAcquisitionSourceOperation.run_id == run.id, ContinuousAcquisitionSourceOperation.intent_state == "intent").values(intent_state="indeterminate", result_state="indeterminate", result_code="lease_expired"))
            run.state = "indeterminate"
            run.terminal_code = "lease_expired"
            run.lease_owner = None
            run.lease_expires_at = None
        discovery_runs = list(self.session.scalars(select(SourceDiscoveryRun).where(SourceDiscoveryRun.lease_expires_at.is_not(None), SourceDiscoveryRun.lease_expires_at < current, SourceDiscoveryRun.state.in_(("planned", "running")))))
        for discovery_run in discovery_runs:
            self.session.execute(update(SourceDiscoveryOperation).where(SourceDiscoveryOperation.run_id == discovery_run.id, SourceDiscoveryOperation.intent_state == "intent").values(intent_state="indeterminate", result_state="indeterminate", result_code="lease_expired"))
            discovery_run.state = "indeterminate"
            discovery_run.terminal_code = "lease_expired"
            discovery_run.lease_owner = None
            discovery_run.lease_expires_at = None
        self.session.commit()
        return len(runs) + len(discovery_runs)
