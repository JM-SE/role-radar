"""Fixtures compartidas: settings, app, cliente HTTP async y DB de test.

DB de test: SQLite in-memory con StaticPool + ``create_all`` sobre el metadata
(patrón §9/§11 de la spec F1 — velocidad; Alembic es el camino de producción).
"""

import os
import socket
from collections.abc import AsyncIterator, Callable, Iterator

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


@pytest.fixture(scope="session", autouse=True)
def deny_external_network() -> Iterator[None]:
    """Gate A session guard; explicit MockTransport seams remain available."""

    if not (
        os.environ.get("ROLE_RADAR_TEST_NETWORK_DENY") == "1"
        or os.environ.get("ROLE_RADAR_TEST_NETWORK") == "deny"
    ):
        yield
        return

    monkeypatch = pytest.MonkeyPatch()
    counters = {
        "socket_connect": 0,
        "socket_create_connection": 0,
        "socket_getaddrinfo": 0,
        "httpx_sync_default_transport": 0,
        "httpx_async_default_transport": 0,
    }

    def denied(name: str) -> Callable[..., None]:
        def _deny(*_args: object, **_kwargs: object) -> None:
            counters[name] += 1
            raise AssertionError("external network is denied during Gate A")

        return _deny

    monkeypatch.setattr(socket.socket, "connect", denied("socket_connect"))
    monkeypatch.setattr(socket, "create_connection", denied("socket_create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", denied("socket_getaddrinfo"))
    monkeypatch.setattr(
        httpx.HTTPTransport,
        "handle_request",
        denied("httpx_sync_default_transport"),
    )
    monkeypatch.setattr(
        httpx.AsyncHTTPTransport,
        "handle_async_request",
        denied("httpx_async_default_transport"),
    )
    try:
        yield
    finally:
        assert all(value == 0 for value in counters.values()), counters
        monkeypatch.undo()


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
