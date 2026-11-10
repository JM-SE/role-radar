"""Fixtures compartidas: settings, app, cliente HTTP async y DB de test.

DB de test: SQLite in-memory con StaticPool + ``create_all`` sobre el metadata
(patrón §9/§11 de la spec F1 — velocidad; Alembic es el camino de producción).
"""

import json
import os
import socket
import tempfile
from collections.abc import AsyncIterator, Callable, Iterator
from functools import partial
from pathlib import Path

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
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository

_synthetic_socket_roots: set[str] = set()


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

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guarded_connect(sock: socket.socket, address: object) -> object:
        if (sock.family == socket.AF_UNIX and isinstance(address, str)
                and str(Path(address).parent) in _synthetic_socket_roots):
            return original_connect(sock, address)
        return denied("socket_connect")(address)

    def guarded_connect_ex(sock: socket.socket, address: object) -> object:
        if (sock.family == socket.AF_UNIX and isinstance(address, str)
                and str(Path(address).parent) in _synthetic_socket_roots):
            return original_connect_ex(sock, address)
        return denied("socket_connect")(address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
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


@pytest.fixture(scope="session")
def synthetic_fence_root() -> Iterator[Path]:
    """One private synthetic fence per pytest worker, cleaned after all patches."""
    with tempfile.TemporaryDirectory(prefix="rrf-") as name:
        root = Path(name)
        root.chmod(0o750)
        lock = root / "execution.lock"
        lock.touch(mode=0o640)
        lock.chmod(0o640)
        api_dir = root / "api"
        api_dir.mkdir(mode=0o700)
        _synthetic_socket_roots.add(str(api_dir))
        _synthetic_socket_roots.add(str(root))
        try:
            yield root
        finally:
            _synthetic_socket_roots.discard(str(api_dir))
            _synthetic_socket_roots.discard(str(root))


@pytest.fixture(autouse=True)
def synthetic_fence(
    monkeypatch: pytest.MonkeyPatch, synthetic_fence_root: Path, request: pytest.FixtureRequest,
) -> Path:
    import role_radar.api.fence_attestation as api_attestation
    import role_radar.fence_runtime as runtime

    monkeypatch.setattr(runtime, "RUNTIME_DIR", str(synthetic_fence_root))
    monkeypatch.setattr(runtime, "LOCK_PATH", str(synthetic_fence_root / "execution.lock"))
    monkeypatch.setattr(runtime, "ROOT_UID", os.getuid())
    monkeypatch.setattr(runtime, "_role_gid", lambda: os.getgid())
    monkeypatch.setattr(api_attestation, "SOCKET_DIR", synthetic_fence_root / "api")
    monkeypatch.setattr(api_attestation, "SERVICE_UID", os.getuid())
    monkeypatch.setattr(api_attestation, "SERVICE_GID", os.getgid())
    if request.path.name != "test_api_fence_attestation.py":
        original_start = api_attestation.FenceAttestationServer.start.__func__

        async def synthetic_start(cls):
            old_umask = os.umask(0o177)
            try:
                return await original_start(cls)
            finally:
                os.umask(old_umask)

        monkeypatch.setattr(
            api_attestation.FenceAttestationServer, "start", classmethod(synthetic_start)
        )
    return synthetic_fence_root


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
def profile_bound_runs(db_session: Session) -> tuple[str, RunRepository]:
    """Bind collection runs to the profile required by intake without changing product code."""
    data = json.loads((Path(__file__).parents[1] / "fixtures" / "profile_seed.json").read_text())
    profile = ProfileRepository(db_session).create_v1(
        name=data["name"], profile_json=data["profile_json"]
    )
    runs = RunRepository(db_session)
    runs.create_run = partial(runs.create_run, profile_id=profile.id)
    return profile.id, runs


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
