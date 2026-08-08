"""Pure source identity functions."""

from typing import Any

from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import GreenhouseSourceConfig


def greenhouse_source_key(board_token: str) -> str:
    config = GreenhouseSourceConfig.model_validate({"board_token": board_token})
    key = f"greenhouse:{config.board_token}"
    if len(key) > 255:
        raise ValueError("source key is too long")
    return key


def legacy_source_key(source_type: SourceType | str, source_id: str) -> str:
    value = source_type.value if isinstance(source_type, SourceType) else str(source_type)
    key = f"legacy:{value}:{source_id}"
    if len(key) > 255:
        raise ValueError("source key is too long")
    return key


def canonical_source_key(source_type: SourceType | str, configuration: dict[str, Any]) -> str:
    value = SourceType(source_type)
    if value is SourceType.GREENHOUSE:
        return greenhouse_source_key(configuration.get("board_token", ""))
    raise ValueError("source type has no canonicalizer")
