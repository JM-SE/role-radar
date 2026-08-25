"""Read-only runtime adapters for the Gate B boundary.

These adapters deliberately expose only immutable DTOs to the live workflow.
They do not call repositories that can mutate rows and do not commit sessions.
"""

from __future__ import annotations

import sqlite3
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, joinedload

from role_radar.acquisition.activation import validate_jobicy_activation
from role_radar.acquisition.jobicy_terms_evidence import load_jobicy_terms_evidence
from role_radar.collectors.outcomes import CollectionFailure, CollectionOutcome, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext, create_collector
from role_radar.db.models import JobSourceReference, Source
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.evaluation.controlled_acquisition.acquisition import CollectorTask
from role_radar.evaluation.controlled_acquisition.contracts import (
    HistoricalIdentity,
    SourceCheckpoint,
)
from role_radar.evaluation.controlled_acquisition.deduplication import (
    build_inventory_index,
    normalize_identity_url,
)
from role_radar.evaluation.controlled_acquisition.source_plan import (
    SourcePlan,
    canonical_json,
)


def _checkpoint(row: Source) -> SourceCheckpoint:
    return SourceCheckpoint(
        source_id=row.id,
        source_type=row.type.value,
        source_key=row.source_key,
        name=row.name,
        revision=row.revision,
        configuration_version=row.configuration_version,
        configuration=dict(row.configuration or {}),
        enabled=bool(row.enabled),
        archived=row.archived_at is not None,
    )


class SqlAlchemySourceState:
    """Explicit-ID, read-only source checkpoint adapter."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def checkpoint(self, source_ids: tuple[str, ...]) -> tuple[SourceCheckpoint, ...]:
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source_ids_not_unique")
        rows = list(self._session.scalars(select(Source).where(Source.id.in_(source_ids))))
        by_id = {row.id: row for row in rows}
        if set(by_id) != set(source_ids):
            raise ValueError("source_not_found")
        return tuple(_checkpoint(by_id[source_id]) for source_id in source_ids)

    def assert_unchanged(self, checkpoint: tuple[SourceCheckpoint, ...]) -> None:
        if not checkpoint:
            return
        current = self.checkpoint(tuple(item.source_id for item in checkpoint))
        if current != checkpoint:
            raise RuntimeError("source_state_changed")

    def assert_all_disabled(self, checkpoint: tuple[SourceCheckpoint, ...]) -> None:
        if any(item.enabled for item in checkpoint):
            raise ValueError("source_must_be_disabled")

    def assert_global_disabled(self) -> None:
        enabled = self._session.scalar(select(Source.id).where(Source.enabled.is_(True)).limit(1))
        if enabled is not None:
            raise ValueError("source_globally_enabled")


class SqlAlchemyHistoricalInventory:
    """One-shot historical identity snapshot, captured before network I/O."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._keys: frozenset[str] | None = None

    def capture(self) -> None:
        rows = self._session.scalars(
            select(JobSourceReference).options(
                joinedload(JobSourceReference.source),
                joinedload(JobSourceReference.job),
            )
        ).unique()
        identities: list[HistoricalIdentity] = []
        for row in rows:
            source_type = row.source.type.value
            identities.append(
                HistoricalIdentity(
                    source_family=source_type,
                    source_key=row.source.source_key,
                    external_id=row.external_id,
                    official_url=normalize_identity_url(row.source_url),
                    application_url=normalize_identity_url(row.job.application_url),
                    description_hash=row.job.description_hash,
                )
            )
        self._keys = build_inventory_index(tuple(identities))

    def capture_before_requests(self) -> None:
        self.capture()

    def strong_keys(self) -> frozenset[str]:
        if self._keys is None:
            raise RuntimeError("historical_inventory_not_captured")
        return self._keys


@dataclass(frozen=True, slots=True)
class CollectorTaskFactory:
    """Build direct collector tasks from an approved plan and DB snapshots."""

    session: Session
    context: CollectorContext

    def build(self, plan: SourcePlan) -> tuple[CollectorTask, ...]:
        source_ids = tuple(str(item["source_id"]) for item in plan.source_configs)
        state = SqlAlchemySourceState(self.session)
        checkpoints = {item.source_id: item for item in state.checkpoint(source_ids)}
        tasks: list[CollectorTask] = []

        async def collect_with_context(
            snapshot: SourceSnapshot, runtime: CollectorRuntime
        ) -> CollectionOutcome:
            return await _collect(snapshot, runtime, self.context)

        for source_config in plan.source_configs:
            source_id = str(source_config["source_id"])
            expected_revision = int(source_config["revision"])
            checkpoint = checkpoints[source_id]
            if checkpoint.revision != expected_revision:
                raise ValueError("source_revision_mismatch")
            if checkpoint.enabled or checkpoint.archived:
                raise ValueError("source_must_be_disabled_and_unarchived")
            expected_family = str(source_config["family"])
            if checkpoint.source_type != expected_family:
                raise ValueError("source_family_mismatch")
            if checkpoint.source_key != source_config.get("source_key"):
                raise ValueError("source_key_mismatch")
            if checkpoint.configuration_version != source_config.get("configuration_version"):
                raise ValueError("configuration_version_mismatch")
            if canonical_json(checkpoint.configuration) != canonical_json(
                source_config.get("configuration")
            ):
                raise ValueError("source_configuration_mismatch")
            snapshot = SourceSnapshot(
                source_id=checkpoint.source_id,
                source_type=checkpoint.source_type,
                name=checkpoint.name,
                configuration=checkpoint.configuration,
                source_key=checkpoint.source_key,
                configuration_version=checkpoint.configuration_version,
            )
            tasks.append(
                CollectorTask(
                    snapshot=snapshot,
                    source_revision=checkpoint.revision,
                    collector=collect_with_context,
                )
            )
        return tuple(tasks)


async def _collect(
    snapshot: SourceSnapshot, runtime: Any, context: CollectorContext
) -> CollectionOutcome:
    collector = create_collector(snapshot, context)
    result = await collector.collect(snapshot, runtime)
    if not isinstance(result, (CollectionSuccess, CollectionFailure)):
        raise TypeError("collector returned an unsupported outcome")
    return result


class SqlAlchemyRuntimeSafety:
    """Read-only guard against normal runs overlapping the evaluation."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def assert_no_active_normal_runs(self) -> None:
        active = tuple(
            self._session.execute(
                text(
                    "SELECT status FROM job_search_runs "
                    "WHERE status IN (:pending, :collecting, :normalizing, "
                    ":extracting, :scoring, :deep_evaluating, :notifying) LIMIT 1"
                ),
                {
                    "pending": "pending",
                    "collecting": "collecting",
                    "normalizing": "normalizing",
                    "extracting": "extracting",
                    "scoring": "scoring",
                    "deep_evaluating": "deep_evaluating",
                    "notifying": "notifying",
                },
            )
        )
        if active:
            raise ValueError("normal_run_active")


def verify_profile_identity(
    session: Session,
    *,
    profile_id: str,
    profile_version: int,
    profile_schema_version: int,
    profile_sha256: str,
) -> None:
    from role_radar.db.models import CandidateProfile

    profile = session.get(CandidateProfile, profile_id)
    if profile is None or not profile.is_active:
        raise ValueError("profile_not_active")
    if (
        profile.version != profile_version
        or profile.schema_version != profile_schema_version
        or canonical_profile_sha256(profile.profile_json) != profile_sha256
    ):
        raise ValueError("profile_identity_mismatch")


def active_profile_identity(session: Session) -> tuple[str, int, int, str]:
    """Return only the active profile identity; never expose profile payload."""
    from role_radar.db.models import CandidateProfile

    rows = list(
        session.scalars(select(CandidateProfile).where(CandidateProfile.is_active.is_(True)))
    )
    if len(rows) != 1:
        raise ValueError("active_profile_count_invalid")
    profile = rows[0]
    return (
        profile.id,
        profile.version,
        profile.schema_version,
        canonical_profile_sha256(profile.profile_json),
    )


def verify_jobicy_plan_terms(plan: SourcePlan) -> None:
    if not any(item.get("family") == "jobicy" for item in plan.source_configs):
        return
    evidence = load_jobicy_terms_evidence(plan.jobicy_terms_sha256 or "")
    reviewed_at = datetime.fromisoformat((plan.jobicy_reviewed_at or "").replace("Z", "+00:00"))
    validate_jobicy_activation(
        evidence,
        terms_sha256=plan.jobicy_terms_sha256,
        reviewed_at=reviewed_at,
        fair_use_ack=plan.jobicy_fair_use_ack,
        preserve_destination_ack=plan.jobicy_destination_ack,
        no_redistribution_ack=plan.jobicy_no_redistribution_ack,
        now=datetime.now(UTC),
    )


def verify_deployment_provenance(
    plan: SourcePlan, *, app_root: Path = Path("/opt/role-radar")
) -> None:
    """Require the deployed marker to match the approved clean provenance."""
    expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    marker = app_root / ".deployed-commit"
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("deployment_provenance_missing")
    values = marker.read_text(encoding="ascii").splitlines()
    if len(values) != 1 or values[0] != plan.source_commit:
        raise ValueError("deployment_commit_mismatch")
    for filename, expected in (
        (".deployed-diff-sha256", plan.source_diff_sha256),
        (".deployed-status-sha256", plan.source_status_sha256),
        (".deployed-alembic-head", plan.alembic_head),
    ):
        path = app_root / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError("deployment_provenance_missing")
        if path.read_text(encoding="ascii").strip() != expected:
            raise ValueError("deployment_provenance_mismatch")
    if plan.source_diff_sha256 != expected_empty or plan.source_status_sha256 != expected_empty:
        raise ValueError("deployment_dirty")


def read_deployment_identity(*, app_root: Path = Path("/opt/role-radar")) -> dict[str, str]:
    """Read clean deployment markers without accepting symlinks or extra lines."""
    names = (
        ".deployed-commit",
        ".deployed-diff-sha256",
        ".deployed-status-sha256",
        ".deployed-alembic-head",
    )
    result: dict[str, str] = {}
    for name in names:
        path = app_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("deployment_provenance_missing")
        lines = path.read_text(encoding="ascii").splitlines()
        if len(lines) != 1:
            raise ValueError("deployment_provenance_invalid")
        result[name] = lines[0]
    return result


def open_readonly_engine(database_url: str) -> Engine:
    """Open the local SQLite DB without the application's WAL write pragma."""
    parsed = make_url(database_url)
    if parsed.get_backend_name() != "sqlite" or parsed.database is None:
        raise ValueError("readonly_sqlite_required")
    path = Path(parsed.database).expanduser().resolve()
    uri = f"file:{path}?mode=ro"
    engine = create_engine(
        "sqlite://",
        creator=lambda: sqlite3.connect(uri, uri=True, check_same_thread=False),
    )

    @event.listens_for(engine, "connect")
    def _query_only(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA query_only=ON")
        cursor.close()

    return engine


@dataclass(slots=True)
class SystemdServiceGuard:
    """Stop only the normal worker/timer and restore exact active states."""

    services: tuple[str, ...] = (
        "role-radar-worker.service",
        "role-radar-scheduler.timer",
    )
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run
    _states: tuple[tuple[str, bool], ...] = field(default=(), init=False)

    def prepare(self) -> None:
        states: list[tuple[str, bool]] = []
        try:
            for service in self.services:
                active = self._is_active(service)
                states.append((service, active))
            self._states = tuple(states)
            for service, active in states:
                if active:
                    self._run("stop", service)
        except Exception:
            self._restore(states)
            raise

    def assert_inactive(self) -> None:
        """Fail closed without changing services before a live discovery run."""
        for service in self.services:
            if self._is_active(service):
                raise ValueError("normal_service_active")

    def restore(self) -> None:
        self._restore(getattr(self, "_states", ()))

    def _is_active(self, service: str) -> bool:
        result = self.runner(
            ("systemctl", "is-active", "--quiet", service),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True
        if result.returncode in {3, 4}:
            return False
        raise RuntimeError("systemd_state_unknown")

    def _run(self, action: str, service: str) -> None:
        self.runner(
            ("systemctl", action, service),
            check=True,
            capture_output=True,
            text=True,
        )

    def _restore(self, states: Sequence[tuple[str, bool]]) -> None:
        for service, was_active in reversed(tuple(states)):
            if was_active:
                self._run("start", service)
