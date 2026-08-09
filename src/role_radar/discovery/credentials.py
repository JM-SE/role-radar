"""Compatibility re-export for the unified acquisition credential boundary."""

from role_radar.acquisition.credentials import (
    CredentialError,
    CredentialHandle,
    CredentialResolver,
    SecretMaterial,
)

__all__ = ["CredentialError", "CredentialHandle", "CredentialResolver", "SecretMaterial"]
