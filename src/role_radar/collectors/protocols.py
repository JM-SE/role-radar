"""Contratos agnósticos a la fuente para collectors persistentes."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from role_radar.collectors.outcomes import CollectionOutcome
from role_radar.collectors.policy import CollectionRunBudget


@dataclass(frozen=True)
class SourceSnapshot:
    """Snapshot inmutable de una ``Source`` fijado en el run.

    El contenido es un DTO y no conserva ninguna referencia a SQLAlchemy.  La
    configuración se valida por el adapter del registry antes de hacer red.
    """

    source_id: str
    source_type: str
    name: str
    configuration: Mapping[str, Any]
    source_key: str | None = None
    configuration_version: int = 0


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


@dataclass(frozen=True)
class CollectorRuntime:
    """Test seams and stage budget; no ORM or provider payload crosses here."""

    transport: httpx.AsyncBaseTransport | None = None
    clock: Callable[[], float] = time.monotonic
    sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep
    budget: CollectionRunBudget | None = None


class JobCollector(Protocol):
    async def collect(
        self, snapshot: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionOutcome: ...
