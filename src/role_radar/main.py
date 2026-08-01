"""Composición de la aplicación FastAPI."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib import metadata
from pathlib import Path

from fastapi import FastAPI

from role_radar.api.health import router as health_router
from role_radar.api.jobs import router as jobs_router
from role_radar.api.profiles import router as profiles_router
from role_radar.config import Settings
from role_radar.db.engine import get_engine
from role_radar.db.session import get_session_factory
from role_radar.logging import configure_logging


def create_app() -> FastAPI:
    """Factory: carga settings, configura logging y compone la aplicación.

    Crea el engine y la sessionmaker en ``app.state`` (patrón F1 §9). La
    migración de esquema es responsabilidad de Alembic (no de create_all en
    producción); los tests crean su propia DB in-memory con create_all.
    """
    settings = Settings()
    configure_logging(settings)

    engine = get_engine(settings.database_url)
    session_factory = get_session_factory(engine)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Asegura el directorio padre de la DB SQLite y libera el engine."""
        if settings.database_url.startswith("sqlite:///"):
            db_path = Path(settings.database_url.removeprefix("sqlite:///"))
            db_path.parent.mkdir(parents=True, exist_ok=True)
        yield
        engine.dispose()

    version = metadata.version("role-radar")
    app = FastAPI(title=settings.app_name, version=version, lifespan=lifespan)
    app.state.settings = settings
    app.state.version = version
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.include_router(health_router)
    app.include_router(profiles_router)
    app.include_router(jobs_router)
    return app


app = create_app()
