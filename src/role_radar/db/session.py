"""Factoría de sesiones SQLAlchemy (sync)."""

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker


def get_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Crea la sessionmaker para la app (una por engine)."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
