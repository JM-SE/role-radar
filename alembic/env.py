"""Entorno Alembic: URL desde Settings, metadata de los modelos de role-radar."""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from role_radar.config import Settings
from role_radar.db import models  # noqa: F401 — registra las tablas en Base.metadata
from role_radar.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# La URL se resuelve en runtime desde la configuración de la app, no desde alembic.ini.
config.set_main_option("sqlalchemy.url", Settings().database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Ejecuta migraciones en modo offline (genera SQL sin conectar)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Ejecuta migraciones en modo online (con engine real)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
