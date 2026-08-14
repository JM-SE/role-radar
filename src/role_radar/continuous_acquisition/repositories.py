"""Narrow SQL repositories with explicit compare-and-fence operations."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import exists, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.continuous_acquisition.contracts import SourceSnapshot
from role_radar.continuous_acquisition.orm import (
    ContinuousAcquisitionRun,
    ContinuousAcquisitionSourceOperation,
    JobIdentityKey,
    SourceDiscoveryOperation,
    SourceDiscoveryRun,
)
from role_radar.db.models import Source


class FenceLostError(RuntimeError):
    """The durable lease no longer belongs to this worker."""


class LeaseOwnedError(ValueError):
    """A live slot is owned by another worker and cannot be executed here."""

    def __init__(self) -> None:
        super().__init__("lease_owned")


def snapshot_payload(snapshot: SourceSnapshot) -> dict[str, Any]:
    return {
        "type": snapshot.source_type,
        "name": snapshot.name,
        "config": dict(snapshot.configuration),
        "revision": snapshot.revision,
        "source_id": snapshot.source_id,
        "source_key": snapshot.source_key,
    }


def snapshot_hash(snapshots: tuple[SourceSnapshot, ...]) -> str:
    payload = [snapshot_payload(item) for item in sorted(snapshots, key=lambda item: item.source_id)]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _lease_is_valid(row: Any, *, owner: str, generation: int) -> bool:
    expires = row.lease_expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return bool(
        row.lease_owner == owner
        and row.fencing_generation == generation
        and (expires is None or expires > datetime.now(UTC))
        and row.state in {"planned", "running"}
    )


def _lease_expired(row: Any, *, now: datetime) -> bool:
    expires = row.lease_expires_at
    if expires is None:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return bool(expires <= now)


class RunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def claim_acquisition(
        self, *, slot_key: str, policy_version: str, snapshots: tuple[SourceSnapshot, ...], owner: str
    ) -> ContinuousAcquisitionRun:
        digest = snapshot_hash(snapshots)
        existing = self.session.scalar(select(ContinuousAcquisitionRun).where(ContinuousAcquisitionRun.slot_key == slot_key))
        if existing is not None:
            if existing.snapshot_hash != digest:
                raise ValueError("snapshot_conflict")
            if existing.state not in {"planned", "running"}:
                return existing
            now = datetime.now(UTC)
            if existing.lease_owner not in {None, owner} and not _lease_expired(existing, now=now):
                raise LeaseOwnedError()
            expired = _lease_expired(existing, now=now)
            existing.lease_owner = owner
            existing.lease_expires_at = now + timedelta(minutes=20)
            if expired:
                existing.fencing_generation += 1
            elif existing.fencing_generation < 1:
                existing.fencing_generation = 1
            return existing
        row = ContinuousAcquisitionRun(
            id=str(uuid4()), slot_key=slot_key, policy_version=policy_version,
            snapshot_hash=digest, snapshot_json=[snapshot_payload(source) for source in snapshots],
            state="running", lease_owner=owner, lease_expires_at=datetime.now(UTC) + timedelta(minutes=20), fencing_generation=1,
        )
        try:
            with self.session.begin_nested():
                self.session.add(row)
                self.session.flush()
            return row
        except IntegrityError:
            existing = self.session.scalar(
                select(ContinuousAcquisitionRun).where(
                    ContinuousAcquisitionRun.slot_key == slot_key
                )
            )
            if existing is None:
                raise ValueError("claim_conflict") from None
            if existing.snapshot_hash != digest:
                raise ValueError("snapshot_conflict") from None
            if existing.state not in {"planned", "running"}:
                return existing
            if existing.lease_owner not in {None, owner} and not _lease_expired(
                existing, now=datetime.now(UTC)
            ):
                raise LeaseOwnedError() from None
            return self.claim_acquisition(
                slot_key=slot_key,
                policy_version=policy_version,
                snapshots=snapshots,
                owner=owner,
            )

    def fence(self, run_id: str, *, owner: str, generation: int) -> None:
        now = datetime.now(UTC)
        result = self.session.execute(
            update(ContinuousAcquisitionRun)
            .where(ContinuousAcquisitionRun.id == run_id, ContinuousAcquisitionRun.lease_owner == owner, ContinuousAcquisitionRun.fencing_generation == generation, ContinuousAcquisitionRun.state.in_(("planned", "running")), ContinuousAcquisitionRun.lease_expires_at.is_not(None), ContinuousAcquisitionRun.lease_expires_at > now)
            .values(heartbeat_at=now)
            .execution_options(synchronize_session=False)
        )
        if getattr(result, "rowcount", 0) != 1:
            raise FenceLostError("fence_lost")

    def create_operation(self, run_id: str, snapshot: SourceSnapshot, *, owner: str | None = None, generation: int | None = None) -> ContinuousAcquisitionSourceOperation:
        run = self.session.get(ContinuousAcquisitionRun, run_id)
        if run is None:
            raise ValueError("run_not_found")
        if owner is not None and generation is not None:
            self.fence(run_id, owner=owner, generation=generation)
        existing = self.session.scalar(select(ContinuousAcquisitionSourceOperation).where(ContinuousAcquisitionSourceOperation.run_id == run_id, ContinuousAcquisitionSourceOperation.source_id == snapshot.source_id))
        encoded = snapshot_payload(snapshot)
        if existing is not None:
            if existing.source_snapshot_json != encoded:
                raise ValueError("snapshot_conflict")
            return existing
        row = ContinuousAcquisitionSourceOperation(
            id=str(uuid4()), run_id=run_id, source_id=snapshot.source_id,
            source_snapshot_json=encoded,
            intent_state="intent",
        )
        self.session.add(row)
        self.session.flush()
        return row

    def finalize_operation(self, operation_id: str, *, owner: str, generation: int, **values: Any) -> None:
        operation = self.session.get(ContinuousAcquisitionSourceOperation, operation_id)
        if operation is None:
            raise ValueError("operation_not_found")
        values["finished_at"] = datetime.now(UTC)
        now = datetime.now(UTC)
        lease = select(ContinuousAcquisitionRun.id).where(
            ContinuousAcquisitionRun.id == operation.run_id,
            ContinuousAcquisitionRun.lease_owner == owner,
            ContinuousAcquisitionRun.fencing_generation == generation,
            ContinuousAcquisitionRun.state.in_(("planned", "running")),
            ContinuousAcquisitionRun.lease_expires_at.is_not(None),
            ContinuousAcquisitionRun.lease_expires_at > now,
        )
        result = self.session.execute(
            update(ContinuousAcquisitionSourceOperation)
            .where(
                ContinuousAcquisitionSourceOperation.id == operation_id,
                ContinuousAcquisitionSourceOperation.run_id == operation.run_id,
                exists(lease),
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if getattr(result, "rowcount", 0) != 1:
            raise FenceLostError("fence_lost")

    def finalize_run(self, run_id: str, *, owner: str, generation: int, **values: Any) -> None:
        """Finalize only while the exact lease fencing tuple is still valid."""
        now = datetime.now(UTC)
        values["finished_at"] = now
        result = self.session.execute(
            update(ContinuousAcquisitionRun)
            .where(
                ContinuousAcquisitionRun.id == run_id,
                ContinuousAcquisitionRun.lease_owner == owner,
                ContinuousAcquisitionRun.fencing_generation == generation,
                ContinuousAcquisitionRun.state.in_(("planned", "running")),
                ContinuousAcquisitionRun.lease_expires_at.is_not(None),
                ContinuousAcquisitionRun.lease_expires_at > now,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if getattr(result, "rowcount", 0) != 1:
            raise FenceLostError("fence_lost")


class DiscoveryRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def claim(self, slot_key: str, *, owner: str, policy_version: str, config_version: str) -> SourceDiscoveryRun:
        existing = self.session.scalar(select(SourceDiscoveryRun).where(SourceDiscoveryRun.slot_key == slot_key))
        if existing is not None:
            if existing.state not in {"planned", "running"}:
                return existing
            now = datetime.now(UTC)
            if existing.lease_owner not in {None, owner} and not _lease_expired(existing, now=now):
                raise LeaseOwnedError()
            expired = _lease_expired(existing, now=now)
            existing.lease_owner = owner
            existing.lease_expires_at = now + timedelta(minutes=20)
            if expired:
                existing.fencing_generation += 1
            elif existing.fencing_generation < 1:
                existing.fencing_generation = 1
            return existing
        row = SourceDiscoveryRun(slot_key=slot_key, state="running", policy_version=policy_version, config_version=config_version, lease_owner=owner, lease_expires_at=datetime.now(UTC) + timedelta(minutes=20), fencing_generation=1)
        try:
            with self.session.begin_nested():
                self.session.add(row)
                self.session.flush()
            return row
        except IntegrityError:
            existing = self.session.scalar(
                select(SourceDiscoveryRun).where(SourceDiscoveryRun.slot_key == slot_key)
            )
            if existing is None:
                raise ValueError("claim_conflict") from None
            if existing.state not in {"planned", "running"}:
                return existing
            if existing.lease_owner not in {None, owner} and not _lease_expired(
                existing, now=datetime.now(UTC)
            ):
                raise LeaseOwnedError() from None
            return self.claim(
                slot_key,
                owner=owner,
                policy_version=policy_version,
                config_version=config_version,
            )

    def fence(self, run_id: str, *, owner: str, generation: int) -> None:
        now = datetime.now(UTC)
        result = self.session.execute(update(SourceDiscoveryRun).where(SourceDiscoveryRun.id == run_id, SourceDiscoveryRun.lease_owner == owner, SourceDiscoveryRun.fencing_generation == generation, SourceDiscoveryRun.state.in_(("planned", "running")), SourceDiscoveryRun.lease_expires_at.is_not(None), SourceDiscoveryRun.lease_expires_at > now).values(heartbeat_at=now).execution_options(synchronize_session=False))
        if getattr(result, "rowcount", 0) != 1:
            raise FenceLostError("fence_lost")

    def intent(self, run_id: str, *, operation_key: str, provider: str, operation_type: str, reserved_capacity: int, owner: str | None = None, generation: int | None = None) -> SourceDiscoveryOperation:
        if owner is not None and generation is not None:
            self.fence(run_id, owner=owner, generation=generation)
        existing = self.session.scalar(select(SourceDiscoveryOperation).where(SourceDiscoveryOperation.run_id == run_id, SourceDiscoveryOperation.operation_key == operation_key))
        if existing is not None:
            return existing
        row = SourceDiscoveryOperation(run_id=run_id, operation_key=operation_key, provider=provider, operation_type=operation_type, reserved_capacity=reserved_capacity, intent_state="intent")
        self.session.add(row)
        self.session.flush()
        return row

    def finalize_operation(
        self, operation_id: str, *, owner: str, generation: int, **values: Any
    ) -> None:
        operation = self.session.get(SourceDiscoveryOperation, operation_id)
        if operation is None:
            raise ValueError("operation_not_found")
        values["finished_at"] = datetime.now(UTC)
        now = datetime.now(UTC)
        lease = select(SourceDiscoveryRun.id).where(
            SourceDiscoveryRun.id == operation.run_id,
            SourceDiscoveryRun.lease_owner == owner,
            SourceDiscoveryRun.fencing_generation == generation,
            SourceDiscoveryRun.state.in_(("planned", "running")),
            SourceDiscoveryRun.lease_expires_at.is_not(None),
            SourceDiscoveryRun.lease_expires_at > now,
        )
        result = self.session.execute(
            update(SourceDiscoveryOperation)
            .where(
                SourceDiscoveryOperation.id == operation_id,
                SourceDiscoveryOperation.run_id == operation.run_id,
                exists(lease),
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if getattr(result, "rowcount", 0) != 1:
            raise FenceLostError("fence_lost")

    def finalize_run(self, run_id: str, *, owner: str, generation: int, **values: Any) -> None:
        values["finished_at"] = datetime.now(UTC)
        now = datetime.now(UTC)
        result = self.session.execute(
            update(SourceDiscoveryRun)
            .where(
                SourceDiscoveryRun.id == run_id,
                SourceDiscoveryRun.lease_owner == owner,
                SourceDiscoveryRun.fencing_generation == generation,
                SourceDiscoveryRun.state.in_(("planned", "running")),
                SourceDiscoveryRun.lease_expires_at.is_not(None),
                SourceDiscoveryRun.lease_expires_at > now,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        if getattr(result, "rowcount", 0) != 1:
            raise FenceLostError("fence_lost")


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def jobs_for_identity(self, *, version: str, kind: str, value: str) -> set[str]:
        return set(self.session.scalars(select(JobIdentityKey.job_id).where(JobIdentityKey.identity_version == version, JobIdentityKey.identity_kind == kind, JobIdentityKey.identity_value == value)))

    def add(self, *, job_id: str, kind: str, version: str, value: str, digest: str) -> JobIdentityKey:
        row = JobIdentityKey(job_id=job_id, identity_kind=kind, identity_version=version, identity_value=value, value_digest=digest)
        self.session.add(row)
        self.session.flush()
        return row


class SourceSnapshotRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def enabled_ats_snapshot(self) -> tuple[SourceSnapshot, ...]:
        rows = self.session.scalars(select(Source).where(Source.enabled.is_(True), Source.archived_at.is_(None), Source.type.in_(("greenhouse", "lever"))).order_by(Source.source_key)).all()
        return tuple(SourceSnapshot(str(row.id), row.source_key, row.type.value, row.name, row.configuration or {}, row.revision) for row in rows)
