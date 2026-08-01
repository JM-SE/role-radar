"""Motor SQLAlchemy: creación y pragmas de SQLite (handoff §11.12)."""

from collections.abc import Callable
from typing import Any

from sqlalchemy import Engine, create_engine, event


def configure_sqlite_pragmas(engine: Engine) -> None:
    """Listener de conexión: WAL mode, foreign keys y busy timeout.

    Aplica SOLO a SQLite (configuración por conexión, no por dialecto).
    """

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor: Callable[[], Any] = dbapi_connection.cursor
        cursor_obj = cursor()
        cursor_obj.execute("PRAGMA journal_mode=WAL")
        cursor_obj.execute("PRAGMA foreign_keys=ON")
        cursor_obj.execute("PRAGMA busy_timeout=5000")
        cursor_obj.close()


def get_engine(database_url: str) -> Engine:
    """Crea el engine para la URL dada, aplicando pragmas en SQLite.

    La capa de repositorios no depende de SQLite (migración futura a
    PostgreSQL); los pragmas son una particularidad del dialecto local.
    """
    engine = create_engine(database_url)
    if database_url.startswith("sqlite"):
        configure_sqlite_pragmas(engine)
    return engine
