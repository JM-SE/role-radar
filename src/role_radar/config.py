"""Configuración de la aplicación (pydantic-settings, prefijo ROLE_RADAR_)."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
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
    http_timeout_seconds: float = Field(default=30.0, gt=0, le=86400)
    http_user_agent: str = "role-radar/0.1 (+homelab)"
    tavily_api_key: SecretStr | None = None
    worker_id: str | None = None
    worker_poll_interval_seconds: float = Field(default=2.0, gt=0, le=300)
    worker_lease_duration_seconds: float = Field(default=600.0, gt=0, le=86400)
    worker_heartbeat_interval_seconds: float = Field(default=30.0, gt=0, le=3600)
    worker_max_recoveries: int = Field(default=5, ge=0, le=100)
    worker_max_stage_attempts: int = Field(default=3, ge=1, le=10)
    worker_retry_base_seconds: float = Field(default=5.0, gt=0, le=3600)
    worker_retry_max_seconds: float = Field(default=300.0, gt=0, le=86400)
    allow_direct_pipeline_writes: bool = False
    schedule_id: str = "daily"
    schedule_hour_utc: int = Field(default=8, ge=0, le=23)
    schedule_minute_utc: int = Field(default=0, ge=0, le=59)

    @model_validator(mode="after")
    def validate_worker_safety(self) -> "Settings":
        if self.environment == "prod" and self.allow_direct_pipeline_writes:
            raise ValueError("direct pipeline writes are forbidden in prod")
        if self.worker_heartbeat_interval_seconds >= self.worker_lease_duration_seconds / 3:
            raise ValueError("worker heartbeat interval must be less than lease / 3")
        external_timeout = max(self.http_timeout_seconds, self.broker_result_timeout_seconds)
        if self.worker_lease_duration_seconds <= external_timeout + 30:
            raise ValueError("worker lease must cover external timeout plus margin")
        if self.worker_retry_base_seconds > self.worker_retry_max_seconds:
            raise ValueError("retry base must not exceed retry maximum")
        return self

    model_config = SettingsConfigDict(env_prefix="ROLE_RADAR_")


@lru_cache
def get_settings() -> Settings:
    """Punto único de acceso a las settings (cacheado)."""
    return Settings()
