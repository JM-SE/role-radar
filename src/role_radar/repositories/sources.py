"""DB-only persistence for sources.

This module intentionally knows neither the catalog nor configuration policy.
The legacy ``create`` helper remains as a compatibility seam for F1-F7 tests;
new control-plane code uses ``create_row`` exclusively.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from role_radar.db.models import JobSearchRun, JobSourceReference, Source
from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import GreenhouseSourceConfig
from role_radar.sources.identity import greenhouse_source_key, legacy_source_key

SourceList = list[Source]


class SourceRepository:
    """SQL I/O only; no availability, identity, or permission decisions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, source_id: str) -> Source | None:
        return self._session.get(Source, source_id)

    def get_by_key(self, source_key: str) -> Source | None:
        return self._session.scalar(select(Source).where(Source.source_key == source_key))

    def get_by_name(self, name: str) -> Source | None:
        return self._session.scalar(select(Source).where(Source.name == name))

    def list(
        self,
        *,
        source_type: SourceType | None = None,
        enabled: bool | None = None,
        archived: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Source]:
        stmt = select(Source).order_by(Source.created_at.asc(), Source.id.asc())
        if source_type is not None:
            stmt = stmt.where(Source.type == source_type)
        if enabled is not None:
            stmt = stmt.where(Source.enabled.is_(enabled))
        if archived is not None:
            stmt = stmt.where(
                Source.archived_at.is_not(None) if archived else Source.archived_at.is_(None)
            )
        return list(self._session.scalars(stmt.limit(limit).offset(offset)))

    def count(
        self,
        *,
        source_type: SourceType | None = None,
        enabled: bool | None = None,
        archived: bool | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(Source)
        if source_type is not None:
            stmt = stmt.where(Source.type == source_type)
        if enabled is not None:
            stmt = stmt.where(Source.enabled.is_(enabled))
        if archived is not None:
            stmt = stmt.where(
                Source.archived_at.is_not(None) if archived else Source.archived_at.is_(None)
            )
        return int(self._session.scalar(stmt) or 0)

    def create_row(
        self,
        *,
        source_id: str,
        source_type: SourceType,
        name: str,
        source_key: str,
        configuration: dict[str, Any] | None,
        configuration_version: int,
        enabled: bool,
        revision: int = 1,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
        archived_at: datetime | None = None,
        last_error_code: str | None = None,
    ) -> Source:
        source = Source(
            id=source_id,
            type=source_type,
            name=name,
            source_key=source_key,
            configuration=configuration,
            configuration_version=configuration_version,
            enabled=enabled,
            revision=revision,
            created_at=created_at or datetime.now(UTC),
            updated_at=updated_at or datetime.now(UTC),
            archived_at=archived_at,
            last_error_code=last_error_code,
        )
        self._session.add(source)
        self._session.flush()
        return source

    def update_cas(
        self, source_id: str, expected_revision: int, changes: Mapping[str, Any]
    ) -> Source | None:
        values = dict(changes)
        values["revision"] = Source.revision + 1
        values["updated_at"] = datetime.now(UTC)
        result = self._session.execute(
            update(Source)
            .where(Source.id == source_id, Source.revision == expected_revision)
            .values(**values)
        )
        self._session.flush()
        if getattr(result, "rowcount", 0) != 1:
            return None
        return self.get(source_id)

    def update_health(
        self,
        source_id: str,
        *,
        last_success_at: datetime | None = None,
        last_error_at: datetime | None = None,
        last_error_code: str | None = None,
    ) -> Source | None:
        source = self.get(source_id)
        if source is None:
            return None
        if last_success_at is not None:
            source.last_success_at = last_success_at
        if last_error_at is not None:
            source.last_error_at = last_error_at
        if last_error_code is not None:
            source.last_error_code = last_error_code
        source.updated_at = datetime.now(UTC)
        self._session.flush()
        return source

    def has_references(self, source_id: str) -> bool:
        return bool(
            self._session.scalar(
                select(JobSourceReference.id)
                .where(JobSourceReference.source_id == source_id)
                .limit(1)
            )
        )

    def has_run_history(self, source_id: str) -> bool:
        for snapshot in self._session.scalars(
            select(JobSearchRun.source_snapshot_json).where(
                JobSearchRun.source_snapshot_json.is_not(None)
            )
        ):
            if isinstance(snapshot, list) and any(
                isinstance(item, dict) and item.get("source_id") == source_id for item in snapshot
            ):
                return True
        return False

    def list_enabled(self, type: SourceType | None = None) -> SourceList:
        return self.list(source_type=type, enabled=True, archived=False, limit=100000, offset=0)

    # Compatibility-only helpers for pre-F8 callers. They remain SQL construction
    # helpers and do not perform an upsert or mutate an existing row by display name.
    def create(
        self,
        *,
        type: SourceType,
        name: str,
        configuration: dict[str, Any] | None = None,
        enabled: bool = True,
    ) -> Source:
        source_id = str(uuid4())
        config = dict(configuration or {})
        version = 0
        if type is SourceType.GREENHOUSE and config.get("board_token"):
            parsed = GreenhouseSourceConfig.model_validate(config)
            config = parsed.model_dump(mode="json", exclude_none=True)
            key = greenhouse_source_key(parsed.board_token)
            version = 1
        else:
            key = legacy_source_key(type, source_id)
        return self.create_row(
            source_id=source_id,
            source_type=type,
            name=name,
            source_key=key,
            configuration=config or None,
            configuration_version=version,
            enabled=enabled,
        )
