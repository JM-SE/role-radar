"""Fixtures compartidas: settings de test, app y cliente HTTP async."""

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from role_radar.api import deps
from role_radar.config import Settings
from role_radar.main import create_app


@pytest.fixture
def settings() -> Settings:
    """Settings explícitas de test (sin depender del entorno)."""
    return Settings(environment="dev", log_level="DEBUG")


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    """App real de Fase 0 con la dependencia de settings sobreescrita."""
    application = create_app()
    application.dependency_overrides[deps.get_settings] = lambda: settings
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Cliente HTTP async sobre la app, sin levantar servidor."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
