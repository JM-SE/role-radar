"""Pure source catalog and configuration contracts."""

from role_radar.mailbox.configuration import EmailSourceConfigV1
from role_radar.sources.configuration import (
    GreenhouseSourceConfig,
    LeverRegion,
    LeverSourceConfigV1,
    validate_configuration,
)
from role_radar.sources.identity import canonical_source_key, legacy_source_key, lever_source_key

__all__ = [
    "EmailSourceConfigV1",
    "GreenhouseSourceConfig",
    "LeverRegion",
    "LeverSourceConfigV1",
    "canonical_source_key",
    "legacy_source_key",
    "lever_source_key",
    "validate_configuration",
]
