"""Versioned, strict source configuration models."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

from role_radar.domain.enums import SourceType

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


def _key_is_forbidden(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized == "board_token":
        return False
    return (
        normalized in _FORBIDDEN_KEY_PARTS
        or normalized in _FORBIDDEN_NETWORK_KEYS
        or any(marker in normalized for marker in (*_FORBIDDEN_KEY_PARTS, *_FORBIDDEN_NETWORK_KEYS))
    )


def _reject_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _key_is_forbidden(key):
                raise ValueError("configuration contains a forbidden key")
            _reject_forbidden_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_forbidden_keys(child)


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
            _reject_forbidden_keys(value)
        return value


def validate_configuration(
    source_type: SourceType, version: int, configuration: dict[str, Any]
) -> BaseModel:
    """Validate one explicitly supported ``(type, version)`` pair."""
    if source_type is not SourceType.GREENHOUSE or version != GreenhouseSourceConfig.VERSION:
        raise ValueError("source configuration version is unavailable")
    return GreenhouseSourceConfig.model_validate(configuration)
