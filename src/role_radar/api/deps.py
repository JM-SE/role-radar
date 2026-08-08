"""Dependencias FastAPI inyectables (seam para tests).

get_session: lee la sessionmaker del estado de la app, commitea al éxito y
hace rollback ante error (una sesión por request).
"""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from role_radar.config import Settings, get_settings
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.runs import RunRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.run_service import RunService
from role_radar.services.source_service import SourceService

__all__ = [
    "Settings",
    "get_job_repository",
    "get_profile_repository",
    "get_run_repository",
    "get_run_service",
    "get_session",
    "get_settings",
    "get_source_repository",
    "get_source_service",
]


def get_session(request: Request) -> Iterator[Session]:
    """Crea la sesión de la request; commit en éxito, rollback en error."""
    session = request.app.state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


SessionDep = Annotated[Session, Depends(get_session)]


def get_profile_repository(session: SessionDep) -> ProfileRepository:
    return ProfileRepository(session)


def get_job_repository(session: SessionDep) -> JobRepository:
    return JobRepository(session)


def get_source_repository(session: SessionDep) -> SourceRepository:
    return SourceRepository(session)


def get_source_service(session: SessionDep) -> SourceService:
    return SourceService(session)


def get_run_repository(session: SessionDep) -> RunRepository:
    return RunRepository(session)


def get_run_service(session: SessionDep) -> RunService:
    return RunService(session)
