"""Registry estático de adapters de sources.

No hay discovery dinámico ni plugins: habilitar un segundo ATS requiere una
decisión explícita y otro adapter. Greenhouse es el único adapter real de F5.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from role_radar.collectors.greenhouse import GreenhouseCollector, GreenhouseSourceConfig
from role_radar.collectors.protocols import JobCollector, SourceSnapshot
from role_radar.domain.enums import SourceType


class CollectorConfigurationError(ValueError):
    """La source no tiene configuración válida o un adapter habilitado."""


@dataclass(frozen=True)
class CollectorContext:
    """Dependencias opcionales de un collector, aisladas del registry."""

    client: Any = None
    timeout: float = 30.0
    user_agent: str = "role-radar/0.1 (+homelab)"


@dataclass(frozen=True)
class CollectorRegistration:
    source_type: SourceType
    factory: Callable[[SourceSnapshot, CollectorContext], JobCollector]


class SourceSnapshotModel(BaseModel):
    """Modelo JSON canónico utilizado al persistir snapshots de run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1)
    source_type: SourceType
    name: str = Field(min_length=1, max_length=255)
    configuration: dict[str, Any]

    def as_snapshot(self) -> SourceSnapshot:
        return SourceSnapshot(
            source_id=self.source_id,
            source_type=self.source_type.value,
            name=self.name,
            configuration=self.configuration,
        )


def _greenhouse_factory(snapshot: SourceSnapshot, context: CollectorContext) -> JobCollector:
    try:
        config = GreenhouseSourceConfig.model_validate(snapshot.configuration)
    except ValueError as exc:
        raise CollectorConfigurationError("invalid greenhouse source configuration") from exc
    return GreenhouseCollector(
        client=context.client,
        timeout=context.timeout,
        user_agent=context.user_agent,
        config=config,
    )


REGISTRY: dict[SourceType, CollectorRegistration] = {
    SourceType.GREENHOUSE: CollectorRegistration(SourceType.GREENHOUSE, _greenhouse_factory)
}


def validate_snapshot(snapshot: SourceSnapshot) -> SourceSnapshot:
    """Valida adapter/type/config y devuelve una copia canónica."""
    try:
        source_type = SourceType(snapshot.source_type)
    except ValueError as exc:
        raise CollectorConfigurationError("unsupported source type") from exc
    registration = REGISTRY.get(source_type)
    if registration is None:
        raise CollectorConfigurationError("source type has no enabled collector")
    if not snapshot.source_id or not snapshot.name:
        raise CollectorConfigurationError("source snapshot identity is invalid")
    if source_type is SourceType.GREENHOUSE:
        try:
            GreenhouseSourceConfig.model_validate(snapshot.configuration)
        except ValueError as exc:
            raise CollectorConfigurationError("invalid greenhouse source configuration") from exc
    return SourceSnapshot(
        source_id=snapshot.source_id,
        source_type=source_type.value,
        name=snapshot.name,
        configuration=dict(snapshot.configuration),
    )


def create_collector(
    snapshot: SourceSnapshot, context: CollectorContext | None = None
) -> JobCollector:
    """Construye el adapter estático para un snapshot ya persistible."""
    valid = validate_snapshot(snapshot)
    registration = REGISTRY[SourceType(valid.source_type)]
    return registration.factory(valid, context or CollectorContext())
