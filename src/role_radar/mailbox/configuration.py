"""Strict external mailbox configuration and worker credential handles."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from role_radar.mailbox.contracts import MailboxDescriptor

_ALIAS = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_HANDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
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
        if value not in {
            "linkedin",
            "indeed",
            "google_alerts",
            "wellfound",
            "generic",
            "auto",
        }:
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
    oauth2_expiry_handle: str | None = Field(default=None, max_length=128)
    app_password_handle: str | None = Field(default=None, max_length=128)
    app_password_2fa_ack: bool = False
    app_password_scope_ack: bool = False
    app_password_revocation_ack: bool = False
    dedicated_account_ack: bool = False

    @field_validator(
        "username_handle",
        "oauth2_handle",
        "oauth2_expiry_handle",
        "app_password_handle",
        "message_hmac_handle",
        "content_hmac_handle",
        mode="before",
    )
    @classmethod
    def validate_handle(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or _HANDLE.fullmatch(value) is None:
            raise ValueError("invalid credential handle")
        return value
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
        if self.auth_mode == "xoauth2" and (
            self.oauth2_handle is None or self.oauth2_expiry_handle is None
        ):
            raise ValueError("XOAUTH2 credential and expiry handles are required")
        if self.auth_mode == "app_password" and self.app_password_handle is None:
            raise ValueError("app-password credential handle is required")
        if self.auth_mode == "app_password" and not (
            self.app_password_2fa_ack
            and self.app_password_scope_ack
            and self.app_password_revocation_ack
        ):
            raise ValueError("app-password risk acknowledgements are required")
        return self

    def descriptor(self) -> MailboxDescriptor:
        return MailboxDescriptor(
            **self.model_dump(
                exclude={
                    "app_password_2fa_ack",
                    "app_password_scope_ack",
                    "app_password_revocation_ack",
                    "dedicated_account_ack",
                }
            )
        )
