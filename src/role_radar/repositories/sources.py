"""Persistencia de fuentes de ofertas (Source)."""

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
