"""Contratos agnósticos a la fuente para collectors persistentes."""

from dataclasses import dataclass
from typing import Any, Protocol

from role_radar.domain.dto import RawJob


@dataclass(frozen=True)
class SourceSnapshot:
    """Snapshot inmutable de una ``Source`` fijado en el run.

    El contenido es un DTO y no conserva ninguna referencia a SQLAlchemy.  La
    configuración se valida por el adapter del registry antes de hacer red.
    """

    source_id: str
    source_type: str
    name: str
    configuration: dict[str, Any]


@dataclass(frozen=True)
class CollectionContext:
    """Compatibilidad F2 para callers del collector Greenhouse.

    F5 ya no expone ``board_token`` en ``JobCollector``; se mantiene este DTO
    únicamente para no romper fixtures y herramientas de desarrollo F2.
    """

    source_id: str
    board_token: str
    company: str | None
    source_name: str = ""


class JobCollector(Protocol):
    async def collect(self, snapshot: SourceSnapshot) -> list[RawJob]: ...
