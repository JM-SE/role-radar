"""Versioned, strict source configuration models."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

from role_radar.domain.enums import SourceType


class LeverRegion(StrEnum):
    GLOBAL = "global"
    EU = "eu"

_BOARD_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_FORBIDDEN_KEY_PARTS = {
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "authorization",
    "cookie",
    "private_key",
    "client_secret",
}
_FORBIDDEN_NETWORK_KEYS = {
    "url",
    "uri",
    "host",
    "hostname",
    "origin",
    "base_url",
    "proxy",
    "headers",
}


def _key_is_forbidden(key: str, *, allow_board_token: bool = False) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if allow_board_token and normalized == "board_token":
        return False
    return (
        normalized in _FORBIDDEN_KEY_PARTS
        or normalized in _FORBIDDEN_NETWORK_KEYS
        or any(marker in normalized for marker in (*_FORBIDDEN_KEY_PARTS, *_FORBIDDEN_NETWORK_KEYS))
    )


def _reject_forbidden_keys(value: Any, *, allow_board_token: bool = False) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _key_is_forbidden(
                key, allow_board_token=allow_board_token
            ):
                raise ValueError("configuration contains a forbidden key")
            _reject_forbidden_keys(child, allow_board_token=allow_board_token)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_forbidden_keys(child, allow_board_token=allow_board_token)


class GreenhouseSourceConfig(BaseModel):
    """Greenhouse v1: only public board identity and display company."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    VERSION: ClassVar[int] = 1

    board_token: StrictStr = Field(min_length=1, max_length=128)
    company: StrictStr | None = Field(default=None, max_length=255)

    @field_validator("board_token", mode="before")
    @classmethod
    def normalize_board_token(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("board_token must be a string")
        normalized = value.strip().lower()
        if not _BOARD_TOKEN.fullmatch(normalized):
            raise ValueError("board_token must be a lowercase public slug")
        return normalized

    @field_validator("company", mode="before")
    @classmethod
    def normalize_company(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("company must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("company must not be empty")
        return normalized

    @model_validator(mode="before")
    @classmethod
    def reject_forbidden_keys(cls, value: Any) -> Any:
        if isinstance(value, dict):
            _reject_forbidden_keys(value, allow_board_token=True)
        return value


_LEVER_SITE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")


class LeverSourceConfigV1(BaseModel):
    """Lever v1 public configuration; origins and authentication are code-owned."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    VERSION: ClassVar[int] = 1

    site: StrictStr = Field(min_length=1, max_length=128)
    region: LeverRegion
    company: StrictStr | None = Field(default=None, max_length=255)

    @field_validator("site", mode="before")
    @classmethod
    def normalize_site(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("site must be a string")
        normalized = value.strip().lower()
        try:
            normalized.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("site must be ASCII") from exc
        if not _LEVER_SITE.fullmatch(normalized):
            raise ValueError("site must be a lowercase public slug")
        return normalized

    @field_validator("region", mode="before")
    @classmethod
    def normalize_region(cls, value: Any) -> LeverRegion:
        if isinstance(value, LeverRegion):
            return value
        if not isinstance(value, str):
            raise TypeError("region must be global or eu")
        try:
            return LeverRegion(value.strip().lower())
        except ValueError as exc:
            raise ValueError("region must be global or eu") from exc

    @field_validator("company", mode="before")
    @classmethod
    def normalize_lever_company(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("company must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("company must not be empty")
        return normalized

    @model_validator(mode="before")
    @classmethod
    def reject_forbidden_keys(cls, value: Any) -> Any:
        if isinstance(value, dict):
            _reject_forbidden_keys(value)
        return value


class JobicySourceConfigV1(BaseModel):
    """Jobicy v1: the LATAM remote feed is entirely code-owned."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    VERSION: ClassVar[int] = 1

    region: Literal["latam"] = "latam"
    remote_only: Literal[True] = True

    @model_validator(mode="before")
    @classmethod
    def reject_forbidden_keys(cls, value: Any) -> Any:
        if isinstance(value, dict):
            _reject_forbidden_keys(value)
        return value


def validate_configuration(
    source_type: SourceType, version: int, configuration: dict[str, Any]
) -> BaseModel:
    """Validate one explicitly supported ``(type, version)`` pair."""
    models: dict[tuple[SourceType, int], type[BaseModel]] = {
        (SourceType.GREENHOUSE, GreenhouseSourceConfig.VERSION): GreenhouseSourceConfig,
        (SourceType.LEVER, LeverSourceConfigV1.VERSION): LeverSourceConfigV1,
        (SourceType.JOBICY, JobicySourceConfigV1.VERSION): JobicySourceConfigV1,
    }
    model = models.get((SourceType(source_type), version))
    if model is None:
        raise ValueError("source configuration version is unavailable")
    return model.model_validate(configuration)
