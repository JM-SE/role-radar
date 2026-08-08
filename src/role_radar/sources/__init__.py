"""Pure source catalog and configuration contracts."""

from role_radar.sources.configuration import GreenhouseSourceConfig, validate_configuration
from role_radar.sources.identity import canonical_source_key, legacy_source_key

__all__ = [
    "GreenhouseSourceConfig",
    "canonical_source_key",
    "legacy_source_key",
    "validate_configuration",
]
