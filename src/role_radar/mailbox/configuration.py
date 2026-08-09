"""Strict external mailbox configuration and worker credential handles."""

from __future__ import annotations

import os
import re
import stat
import tomllib
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from role_radar.mailbox.contracts import CredentialMaterial, MailboxDescriptor

_ALIAS = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_AUTH = {"xoauth2", "app_password"}


class EmailSourceConfigV1(BaseModel):
    """Only the two non-secret values that may cross into the database."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    VERSION: ClassVar[int] = 1

    connection_alias: str = Field(min_length=1, max_length=64)
    parser_profile: str = Field(min_length=1, max_length=32)

    @field_validator("connection_alias", mode="before")
    @classmethod
    def normalize_alias(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("connection_alias must be a string")
        value = value.strip().lower()
        if not _ALIAS.fullmatch(value):
            raise ValueError("invalid connection alias")
        return str(value)

    @field_validator("parser_profile", mode="before")
    @classmethod
    def normalize_profile(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("parser_profile must be a string")
        value = value.strip().lower()
        if value not in {"linkedin", "indeed", "google_alerts", "wellfound", "generic"}:
            raise ValueError("parser profile is not allowlisted")
        return str(value)


class ExternalMailboxConfig(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    connection_alias: str = Field(min_length=1, max_length=64)
    protocol: str
    host: str
    port: int
    tls: bool
    validate_certificate: bool
    mailbox: str
    readonly: bool
    auth_mode: str
    username_handle: str = Field(min_length=1, max_length=128)
    oauth2_handle: str | None = Field(default=None, max_length=128)
    app_password_handle: str | None = Field(default=None, max_length=128)
    app_password_2fa_ack: bool = False
    app_password_scope_ack: bool = False
    message_hmac_handle: str = Field(default="mailbox-message-hmac", max_length=128)
    content_hmac_handle: str = Field(default="mailbox-content-hmac", max_length=128)

    @model_validator(mode="after")
    def exact_gmail_policy(self) -> ExternalMailboxConfig:
        if self.protocol != "imap" or self.host != "imap.gmail.com" or self.port != 993:
            raise ValueError("only Gmail IMAP TLS 993 is supported")
        if not self.tls or not self.validate_certificate or self.mailbox != "RoleRadar":
            raise ValueError("Gmail mailbox policy mismatch")
        if not self.readonly or self.auth_mode not in _AUTH:
            raise ValueError("readonly and allowlisted auth are required")
        if self.auth_mode == "xoauth2" and self.oauth2_handle is None:
            raise ValueError("XOAUTH2 credential handle is required")
        if self.auth_mode == "app_password" and self.app_password_handle is None:
            raise ValueError("app-password credential handle is required")
        if self.auth_mode == "app_password" and not (
            self.app_password_2fa_ack and self.app_password_scope_ack
        ):
            raise ValueError("app-password risk acknowledgements are required")
        return self

    def descriptor(self) -> MailboxDescriptor:
        return MailboxDescriptor(
            **self.model_dump(
                exclude={"app_password_2fa_ack", "app_password_scope_ack"}
            )
        )


class AcquisitionConfiguration(BaseModel):
    """Schema for ``/etc/role-radar/acquisition.toml``.

    The TOML contains handles only.  Values are resolved by the worker after
    the plan has been frozen.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    schema_version: int = 1
    config_version: str = "acquisition-v1"
    mailboxes: dict[str, ExternalMailboxConfig]

    @model_validator(mode="after")
    def aliases_match(self) -> AcquisitionConfiguration:
        if set(self.mailboxes) != {item.connection_alias for item in self.mailboxes.values()}:
            raise ValueError("mailbox aliases must be unique and match their descriptors")
        return self


class FileCredentialResolver:
    """Resolve worker-only files.  This class intentionally has no DB/API use."""

    def __init__(self, files: dict[str, Path]) -> None:
        self._files = dict(files)

    def __call__(self, descriptor: MailboxDescriptor) -> CredentialMaterial:
        username = self._read(descriptor.username_handle)
        oauth = (
            self._read(descriptor.oauth2_handle) if descriptor.oauth2_handle is not None else None
        )
        password = (
            self._read(descriptor.app_password_handle)
            if descriptor.app_password_handle is not None
            else None
        )
        return CredentialMaterial(username=username, oauth2_token=oauth, app_password=password)

    def _read(self, handle: str) -> str:
        path = self._files.get(handle)
        if path is None or path.stat().st_mode & 0o077:
            raise ValueError("credential unavailable")
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError("credential unavailable")
        return value


def load_acquisition_configuration(path: str | Path) -> AcquisitionConfiguration:
    candidate = Path(path)
    try:
        metadata = candidate.stat()
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid not in {0, os.geteuid()}
        ):
            raise ValueError("acquisition config must be a private regular file")
        with candidate.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("acquisition config unavailable") from exc
    return AcquisitionConfiguration.model_validate(raw)


def resolve_descriptor(config: AcquisitionConfiguration, alias: str) -> MailboxDescriptor:
    try:
        return config.mailboxes[alias].descriptor()
    except KeyError as exc:
        raise ValueError("mailbox descriptor unavailable") from exc
