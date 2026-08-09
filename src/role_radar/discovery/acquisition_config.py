"""Compatibility imports for the unified acquisition configuration.

The canonical model and loader live in :mod:`role_radar.acquisition.configuration`.
This module intentionally contains no second schema or filesystem implementation.
"""

from role_radar.acquisition.configuration import (
    BRAVE_PAID_LOCAL_CAP_MICRO_USD,
    DEFAULT_ACQUISITION_CONFIG,
    AcquisitionConfig,
    AcquisitionConfigError,
    BravePaidConfig,
    FreeQuota,
    JobicyTermsConfig,
    load_acquisition_config,
)

__all__ = [
    "BRAVE_PAID_LOCAL_CAP_MICRO_USD",
    "DEFAULT_ACQUISITION_CONFIG",
    "AcquisitionConfig",
    "AcquisitionConfigError",
    "BravePaidConfig",
    "FreeQuota",
    "JobicyTermsConfig",
    "load_acquisition_config",
]
