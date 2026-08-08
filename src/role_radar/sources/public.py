"""Allowlisted public projections for source configuration."""

from typing import Any

from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import GreenhouseSourceConfig, validate_configuration
from role_radar.sources.contracts import PublicSourceConfiguration


def project_public_configuration(
    source_type: SourceType | str, version: int, configuration: dict[str, Any] | None
) -> PublicSourceConfiguration | dict[str, str]:
    """Return a new allowlisted DTO; never return the ORM JSON mapping."""
    value = SourceType(source_type)
    if value is not SourceType.GREENHOUSE or version != GreenhouseSourceConfig.VERSION:
        return {}
    config = validate_configuration(value, version, dict(configuration or {}))
    assert isinstance(config, GreenhouseSourceConfig)
    return PublicSourceConfiguration(config.board_token, config.company)
