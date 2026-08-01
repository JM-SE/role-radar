"""Contratos de collectors y contexto de un board."""

from dataclasses import dataclass
from typing import Protocol

from role_radar.domain.dto import RawJob


@dataclass(frozen=True)
class CollectionContext:
    source_id: str
    board_token: str
    company: str | None
    source_name: str = ""


class JobCollector(Protocol):
    async def collect(self, context: CollectionContext) -> list[RawJob]: ...
