"""Configuración de la aplicación (pydantic-settings, prefijo ROLE_RADAR_)."""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings de role-radar, cargadas desde variables de entorno (prefijo ROLE_RADAR_)."""

    app_name: str = "role-radar"
    environment: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"
    database_url: str = "sqlite:///./data/role-radar.db"
    broker_url: str | None = None
    telegram_bot_token: SecretStr | None = None
    http_timeout_seconds: float = 30.0
    http_user_agent: str = "role-radar/0.1 (+homelab)"
    tavily_api_key: SecretStr | None = None

    model_config = SettingsConfigDict(env_prefix="ROLE_RADAR_")


@lru_cache
def get_settings() -> Settings:
    """Punto único de acceso a las settings (cacheado)."""
    return Settings()
