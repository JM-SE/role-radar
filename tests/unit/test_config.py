"""Tests de role_radar.config."""

import pytest
from pydantic import SecretStr

from role_radar.config import Settings

_ENV_KEYS = (
    "ROLE_RADAR_APP_NAME",
    "ROLE_RADAR_ENVIRONMENT",
    "ROLE_RADAR_LOG_LEVEL",
    "ROLE_RADAR_DATABASE_URL",
    "ROLE_RADAR_BROKER_URL",
    "ROLE_RADAR_TELEGRAM_BOT_TOKEN",
)


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)

    settings = Settings()

    assert settings.app_name == "role-radar"
    assert settings.environment == "dev"
    assert settings.log_level == "INFO"
    assert settings.database_url is None
    assert settings.broker_url is None
    assert settings.telegram_bot_token is None


def test_settings_override_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROLE_RADAR_ENVIRONMENT", "prod")
    monkeypatch.setenv("ROLE_RADAR_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("ROLE_RADAR_DATABASE_URL", "sqlite:///./test.db")

    settings = Settings()

    assert settings.environment == "prod"
    assert settings.log_level == "DEBUG"
    assert settings.database_url == "sqlite:///./test.db"


def test_settings_secrets_not_exposed_in_repr() -> None:
    settings = Settings(telegram_bot_token=SecretStr("super-secret-token"))

    assert "super-secret-token" not in repr(settings)
    assert settings.telegram_bot_token is not None
    assert settings.telegram_bot_token.get_secret_value() == "super-secret-token"
