"""Composición de la aplicación FastAPI."""

from importlib import metadata

from fastapi import FastAPI

from role_radar.api.health import router as health_router
from role_radar.config import Settings
from role_radar.logging import configure_logging


def create_app() -> FastAPI:
    """Factory: carga settings, configura logging y compone la aplicación."""
    settings = Settings()
    configure_logging(settings)

    version = metadata.version("role-radar")
    app = FastAPI(title=settings.app_name, version=version)
    app.state.settings = settings
    app.state.version = version
    app.include_router(health_router)
    return app


app = create_app()
