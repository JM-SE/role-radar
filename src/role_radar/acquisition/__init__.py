"""Stable, side-effect-free acquisition contracts."""

from role_radar.acquisition.configuration import (
    AcquisitionConfig,
    AcquisitionConfigError,
    DevelopmentAcquisitionFilePolicy,
    ProductionAcquisitionFilePolicy,
    load_acquisition_config,
)
from role_radar.acquisition.credentials import CredentialHandle, CredentialResolver

__all__ = [
    "AcquisitionConfig",
    "AcquisitionConfigError",
    "CredentialHandle",
    "CredentialResolver",
    "DevelopmentAcquisitionFilePolicy",
    "ProductionAcquisitionFilePolicy",
    "load_acquisition_config",
]
