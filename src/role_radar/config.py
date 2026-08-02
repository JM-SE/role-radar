"""Configuración de la aplicación (pydantic-settings, prefijo ROLE_RADAR_)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings de role-radar, cargadas desde variables de entorno (prefijo ROLE_RADAR_)."""

    app_name: str = "role-radar"
    environment: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"
    database_url: str = "sqlite:///./data/role-radar.db"
    llm_provider: Literal["fake", "broker"] = "fake"
    broker_url: str | None = None
    broker_token: SecretStr | None = None
    broker_workload: str = "role-radar"
    broker_structured_extraction_capability: str = "structured-extraction"
    broker_prefer_wait_seconds: int = Field(default=10, ge=0, le=30)
    broker_poll_interval_seconds: float = Field(default=1.0, gt=0)
    broker_result_timeout_seconds: float = Field(default=300.0, gt=0)
    broker_submit_reconcile_attempts: int = Field(default=3, ge=1)
    telegram_bot_token: SecretStr | None = None
    http_timeout_seconds: float = 30.0
    http_user_agent: str = "role-radar/0.1 (+homelab)"
    tavily_api_key: SecretStr | None = None

    model_config = SettingsConfigDict(env_prefix="ROLE_RADAR_")


@lru_cache
def get_settings() -> Settings:
    """Punto único de acceso a las settings (cacheado)."""
    return Settings()
