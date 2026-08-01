"""Fixtures compartidas: settings, app, cliente HTTP async y DB de test.

DB de test: SQLite in-memory con StaticPool + ``create_all`` sobre el metadata
(patrón §9/§11 de la spec F1 — velocidad; Alembic es el camino de producción).
"""

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from role_radar.api import deps
from role_radar.config import Settings
from role_radar.db.base import Base
from role_radar.main import create_app


@pytest.fixture
def settings() -> Settings:
    """Settings explícitas de test (sin depender del entorno)."""
    return Settings(environment="dev", log_level="DEBUG")


@pytest.fixture
def db_engine() -> Iterator[Engine]:
    """Engine SQLite in-memory con el esquema completo (create_all)."""
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Sesión de test sobre la DB in-memory (una por test)."""
    with Session(db_engine) as session:
        yield session


@pytest.fixture
def app(settings: Settings, db_session: Session) -> FastAPI:
    """App real con overrides: settings de test y sesión de DB de test.

    get_session se sobreescribe para apuntar a la DB in-memory; el commit
    ocurre al cerrar cada request (mismo contrato que en producción).
    """
    application = create_app()
    application.dependency_overrides[deps.get_settings] = lambda: settings

    def _override_get_session() -> Iterator[Session]:
        yield db_session
        db_session.commit()

    application.dependency_overrides[deps.get_session] = _override_get_session
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Cliente HTTP async sobre la app, sin levantar servidor."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
