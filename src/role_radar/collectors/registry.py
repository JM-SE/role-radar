"""Static collector factory registry.

Availability and CRUD policy live in ``sources.catalog`` and
``services.source_service``. This module only resolves the one approved
Greenhouse factory from an already validated DTO.
"""

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.protocols import JobCollector, SourceSnapshot
from role_radar.domain.enums import SourceType
from role_radar.sources.catalog import CATALOG, get_catalog_entry
from role_radar.sources.configuration import GreenhouseSourceConfig, validate_configuration
from role_radar.sources.identity import canonical_source_key, legacy_source_key


class CollectorConfigurationError(ValueError):
    """Snapshot cannot be used by a registered adapter."""


@dataclass(frozen=True)
class CollectorContext:
    client: Any = None
    timeout: float = 30.0
    user_agent: str = "role-radar/0.1 (+homelab)"


@dataclass(frozen=True)
class CollectorRegistration:
    source_type: SourceType
    factory_ref: str
    factory: Callable[[SourceSnapshot, CollectorContext], JobCollector]


class SourceSnapshotModel(BaseModel):
    """Persisted v0/v1 snapshot shape, with strict unknown-field rejection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1)
    source_type: SourceType
    name: str = Field(min_length=1, max_length=255)
    configuration: dict[str, Any]
    source_key: str | None = None
    configuration_version: int = 0

    @model_validator(mode="after")
    def validate_version(self) -> "SourceSnapshotModel":
        if self.configuration_version not in (0, 1):
            raise ValueError("unsupported source snapshot version")
        return self

    def as_snapshot(self) -> SourceSnapshot:
        source_key = self.source_key
        version = self.configuration_version
        if self.source_type is SourceType.GREENHOUSE:
            try:
                config = GreenhouseSourceConfig.model_validate(self.configuration)
                calculated_key = canonical_source_key(self.source_type, config.model_dump())
                if source_key is not None and source_key != calculated_key:
                    raise ValueError("snapshot source key does not match configuration")
                source_key = source_key or calculated_key
                version = version or GreenhouseSourceConfig.VERSION
            except ValueError as exc:
                raise CollectorConfigurationError(
                    "invalid greenhouse source configuration"
                ) from exc
        elif source_key is None:
            source_key = legacy_source_key(self.source_type, self.source_id)
        return SourceSnapshot(
            source_id=self.source_id,
            source_type=self.source_type.value,
            name=self.name,
            configuration=MappingProxyType(dict(self.configuration)),
            source_key=source_key,
            configuration_version=version,
        )


def _greenhouse_factory(snapshot: SourceSnapshot, context: CollectorContext) -> JobCollector:
    try:
        config = validate_configuration(
            SourceType.GREENHOUSE,
            snapshot.configuration_version or GreenhouseSourceConfig.VERSION,
            dict(snapshot.configuration),
        )
    except ValueError as exc:
        raise CollectorConfigurationError("invalid greenhouse source configuration") from exc
    assert isinstance(config, GreenhouseSourceConfig)
    return GreenhouseCollector(
        client=context.client,
        timeout=context.timeout,
        user_agent=context.user_agent,
        config=config,
    )


def _factory_map() -> dict[str, CollectorRegistration]:
    return {
        "greenhouse.v1": CollectorRegistration(
            SourceType.GREENHOUSE, "greenhouse.v1", _greenhouse_factory
        )
    }


FACTORIES = _factory_map()
# The public registry contract is factory_ref -> callable. The type-indexed
# view is intentionally separate and is not used for availability decisions.
REGISTRY = {factory_ref: registration.factory for factory_ref, registration in FACTORIES.items()}
REGISTRATIONS_BY_TYPE = {
    registration.source_type: registration for registration in FACTORIES.values()
}

if set(REGISTRY) != {entry.factory_ref for entry in CATALOG.values() if entry.factory_ref}:
    raise AssertionError("catalog and collector factory references diverge")


def validate_snapshot(snapshot: SourceSnapshot) -> SourceSnapshot:
    """Validate adapter/config without opening a network client."""
    try:
        source_type = SourceType(snapshot.source_type)
        entry = get_catalog_entry(source_type)
    except (KeyError, ValueError) as exc:
        raise CollectorConfigurationError("unsupported source type") from exc
    if not entry.adapter_available or entry.factory_ref is None:
        raise CollectorConfigurationError("source type has no enabled collector")
    if snapshot.configuration_version not in (0, GreenhouseSourceConfig.VERSION):
        raise CollectorConfigurationError("unsupported source configuration version")
    try:
        config = GreenhouseSourceConfig.model_validate(dict(snapshot.configuration))
        calculated_key = canonical_source_key(source_type, config.model_dump())
        if snapshot.source_key is not None and snapshot.source_key != calculated_key:
            raise ValueError("snapshot source key does not match configuration")
        source_key = snapshot.source_key or calculated_key
    except ValueError as exc:
        raise CollectorConfigurationError("invalid greenhouse source configuration") from exc
    return SourceSnapshot(
        source_id=snapshot.source_id,
        source_type=source_type.value,
        name=snapshot.name,
        configuration=MappingProxyType(config.model_dump(mode="json", exclude_none=True)),
        source_key=source_key,
        configuration_version=GreenhouseSourceConfig.VERSION,
    )


def create_collector(
    snapshot: SourceSnapshot, context: CollectorContext | None = None
) -> JobCollector:
    valid = validate_snapshot(snapshot)
    entry = get_catalog_entry(valid.source_type)
    factory = REGISTRY.get(entry.factory_ref or "")
    if factory is None:
        raise CollectorConfigurationError("collector factory is unavailable")
    return factory(valid, context or CollectorContext())
