"""Persistencia de fuentes de ofertas (Source)."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import Source
from role_radar.domain.enums import SourceType


class SourceRepository:
    """I/O de Source. Sin reglas de negocio ni commit propio."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        type: SourceType,
        name: str,
        configuration: dict[str, Any] | None = None,
        enabled: bool = True,
    ) -> Source:
        source = Source(
            type=type,
            name=name,
            configuration=configuration,
            enabled=enabled,
        )
        self._session.add(source)
        self._session.flush()
        return source

    def get(self, source_id: str) -> Source | None:
        return self._session.get(Source, source_id)

    def get_by_name(self, name: str) -> Source | None:
        stmt = select(Source).where(Source.name == name)
        return self._session.scalars(stmt).first()

    def list_enabled(self, type: SourceType | None = None) -> list[Source]:
        stmt = select(Source).where(Source.enabled.is_(True)).order_by(Source.name)
        if type is not None:
            stmt = stmt.where(Source.type == type)
        return list(self._session.scalars(stmt))

    def update_last_success(
        self, source_id: str, *, at: datetime | None = None
    ) -> Source | None:
        source = self._session.get(Source, source_id)
        if source is None:
            return None
        source.last_success_at = at or datetime.now(UTC)
        self._session.flush()
        return source

    def update_last_error(self, source_id: str, *, at: datetime | None = None) -> Source | None:
        source = self._session.get(Source, source_id)
        if source is None:
            return None
        source.last_error_at = at or datetime.now(UTC)
        self._session.flush()
        return source

    def upsert_greenhouse_board(
        self,
        *,
        name: str,
        board_token: str,
        company: str | None = None,
        enabled: bool = False,
    ) -> Source:
        source = self.get_by_name(name)
        configuration: dict[str, Any] = {"board_token": board_token}
        if company is not None:
            configuration["company"] = company
        if source is None:
            source = self.create(
                type=SourceType.GREENHOUSE,
                name=name,
                configuration=configuration,
                enabled=enabled,
            )
        else:
            existing = source.configuration or {}
            existing.update(configuration)
            source.type = SourceType.GREENHOUSE
            source.configuration = existing
            self._session.flush()
        return source
