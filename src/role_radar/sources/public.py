"""Allowlisted public projections for source configuration."""

from typing import Any

from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import (
    GreenhouseSourceConfig,
    JobicySourceConfigV1,
    LeverSourceConfigV1,
    validate_configuration,
)
from role_radar.sources.contracts import (
    PublicJobicySourceConfiguration,
    PublicLeverSourceConfiguration,
    PublicSourceConfiguration,
)


def project_public_configuration(
    source_type: SourceType | str, version: int, configuration: dict[str, Any] | None
) -> (
    PublicSourceConfiguration
    | PublicLeverSourceConfiguration
    | PublicJobicySourceConfiguration
    | dict[str, str]
):
    """Return a new allowlisted DTO; never return the ORM JSON mapping."""
    value = SourceType(source_type)
    if value is SourceType.GREENHOUSE and version != GreenhouseSourceConfig.VERSION:
        return {}
    if value is SourceType.LEVER and version != LeverSourceConfigV1.VERSION:
        return {}
    if value is SourceType.JOBICY and version != JobicySourceConfigV1.VERSION:
        return {}
    if value not in {SourceType.GREENHOUSE, SourceType.LEVER, SourceType.JOBICY}:
        return {}
    config = validate_configuration(value, version, dict(configuration or {}))
    if isinstance(config, GreenhouseSourceConfig):
        return PublicSourceConfiguration(config.board_token, config.company)
    if isinstance(config, JobicySourceConfigV1):
        return PublicJobicySourceConfiguration(
            config.region, str(config.remote_only).lower(), f"v{config.VERSION}"
        )
    assert isinstance(config, LeverSourceConfigV1)
    return PublicLeverSourceConfiguration(config.site, config.region.value, config.company)
