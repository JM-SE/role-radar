"""F8.1 source catalog/control-plane schema.

The audits intentionally run before any DDL. A failed backfill therefore does
not leave a partially upgraded SQLite schema or silently choose a winner.
"""

import json
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa

from alembic import op
from role_radar.domain.enums import SourceType
from role_radar.sources.configuration import GreenhouseSourceConfig
from role_radar.sources.identity import greenhouse_source_key, legacy_source_key

revision: str = "b8c1d4e6f901"
down_revision: str | None = "7f0a4c2d9e11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FORBIDDEN_KEYS = {
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "authorization",
    "cookie",
    "private_key",
    "client_secret",
    "url",
    "uri",
    "host",
    "hostname",
    "origin",
    "base_url",
    "proxy",
    "headers",
}


def _audit_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized != "board_token" and (
                normalized in _FORBIDDEN_KEYS
                or any(marker in normalized for marker in _FORBIDDEN_KEYS)
            ):
                raise RuntimeError("source_catalog_migration_aborted: forbidden config key")
            _audit_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _audit_keys(child)


def _source_rows(connection: sa.Connection) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(sa.text("SELECT * FROM sources")).mappings()]


def _audit(connection: sa.Connection) -> dict[str, tuple[str, dict[str, Any] | None]]:
    duplicate_refs = connection.execute(
        sa.text(
            "SELECT source_id, external_id, COUNT(*) AS n "
            "FROM job_source_references WHERE external_id IS NOT NULL "
            "GROUP BY source_id, external_id HAVING COUNT(*) > 1"
        )
    ).all()
    if duplicate_refs:
        raise RuntimeError("source_catalog_migration_aborted: duplicate source reference")

    result: dict[str, tuple[str, dict[str, Any] | None]] = {}
    for row in _source_rows(connection):
        source_id = str(row["id"])
        try:
            source_type = SourceType(str(row["type"]))
        except ValueError as exc:
            raise RuntimeError("source_catalog_migration_aborted: ambiguous source type") from exc
        configuration = row.get("configuration")
        if isinstance(configuration, str):
            try:
                configuration = json.loads(configuration)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "source_catalog_migration_aborted: invalid configuration JSON"
                ) from exc
        _audit_keys(configuration)
        if source_type is SourceType.GREENHOUSE:
            if not isinstance(configuration, dict):
                raise RuntimeError("source_catalog_migration_aborted: invalid greenhouse config")
            try:
                parsed = GreenhouseSourceConfig.model_validate(configuration)
                key = greenhouse_source_key(parsed.board_token)
            except ValueError as exc:
                raise RuntimeError(
                    "source_catalog_migration_aborted: invalid greenhouse config"
                ) from exc
            normalized_configuration: dict[str, Any] | None = parsed.model_dump(
                mode="json", exclude_none=True
            )
        else:
            key = legacy_source_key(source_type, source_id)
            normalized_configuration = configuration if isinstance(configuration, dict) else None
        if any(existing_key == key for existing_key, _ in result.values()):
            raise RuntimeError("source_catalog_migration_aborted: duplicate source key")
        result[source_id] = (key, normalized_configuration)
    return result


def _rebuild_sources(connection: sa.Connection, *, downgrade: bool = False) -> None:
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    if downgrade:
        connection.exec_driver_sql(
            """CREATE TABLE sources_new (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                type VARCHAR(24) NOT NULL,
                name VARCHAR(255) NOT NULL UNIQUE,
                configuration JSON,
                enabled BOOLEAN NOT NULL,
                last_success_at DATETIME,
                last_error_at DATETIME,
                created_at DATETIME NOT NULL
            )"""
        )
        connection.exec_driver_sql(
            """INSERT INTO sources_new
                (id, type, name, configuration, enabled, last_success_at, last_error_at, created_at)
                SELECT id, type, name, configuration, enabled, last_success_at,
                       last_error_at, created_at
                FROM sources"""
        )
    else:
        connection.exec_driver_sql(
            """CREATE TABLE sources_new (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                type VARCHAR(24) NOT NULL,
                name VARCHAR(255) NOT NULL,
                configuration JSON,
                enabled BOOLEAN NOT NULL,
                source_key VARCHAR(255) NOT NULL,
                configuration_version INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                updated_at DATETIME NOT NULL,
                archived_at DATETIME,
                last_error_code VARCHAR(128),
                last_success_at DATETIME,
                last_error_at DATETIME,
                created_at DATETIME NOT NULL,
                CONSTRAINT uq_sources_source_key UNIQUE (source_key),
                CONSTRAINT ck_sources_revision CHECK (revision >= 1),
                CONSTRAINT ck_sources_archived_disabled CHECK (archived_at IS NULL OR enabled = 0)
            )"""
        )
        connection.exec_driver_sql(
            """INSERT INTO sources_new
                (id, type, name, configuration, enabled, source_key, configuration_version,
                 revision, updated_at, archived_at, last_error_code, last_success_at,
                 last_error_at, created_at)
                SELECT id, type, name, configuration, enabled, source_key, configuration_version,
                 revision, updated_at, archived_at, last_error_code, last_success_at,
                 last_error_at, created_at
                FROM sources"""
        )
    connection.exec_driver_sql("DROP TABLE sources")
    connection.exec_driver_sql("ALTER TABLE sources_new RENAME TO sources")
    connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.1 source catalog migration currently supports SQLite only")

    source_keys = _audit(connection)
    op.add_column("sources", sa.Column("source_key", sa.String(length=255), nullable=True))
    op.add_column("sources", sa.Column("configuration_version", sa.Integer(), nullable=True))
    op.add_column("sources", sa.Column("revision", sa.Integer(), nullable=True))
    op.add_column("sources", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("sources", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("sources", sa.Column("last_error_code", sa.String(length=128), nullable=True))

    json_sources = sa.table(
        "sources", sa.column("id", sa.String()), sa.column("configuration", sa.JSON())
    )
    for source_id, (source_key, normalized_configuration) in source_keys.items():
        source_row = connection.execute(
            sa.text("SELECT type, enabled FROM sources WHERE id = :id"), {"id": source_id}
        ).one()
        source_type, old_enabled = source_row
        version = 1 if source_type == SourceType.GREENHOUSE.value else 0
        connection.execute(
            sa.text(
                "UPDATE sources SET source_key=:key, configuration_version=:version, "
                "revision=1, updated_at=created_at, archived_at=NULL, last_error_code=NULL, "
                "enabled=:enabled "
                "WHERE id=:id"
            ),
            {
                "id": source_id,
                "key": source_key,
                "version": version,
                "enabled": int(bool(old_enabled)) if version == 1 else 0,
            },
        )
        if normalized_configuration is not None:
            connection.execute(
                sa.update(json_sources)
                .where(json_sources.c.id == source_id)
                .values(configuration=normalized_configuration)
            )
    _rebuild_sources(connection)
    connection.exec_driver_sql(
        "CREATE UNIQUE INDEX uq_job_source_references_source_external "
        "ON job_source_references (source_id, external_id) WHERE external_id IS NOT NULL"
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.1 source catalog downgrade currently supports SQLite only")
    duplicates = connection.execute(
        sa.text("SELECT name, COUNT(*) FROM sources GROUP BY name HAVING COUNT(*) > 1")
    ).all()
    if duplicates:
        raise RuntimeError("source_catalog_downgrade_aborted: duplicate source names")
    connection.exec_driver_sql("DROP INDEX IF EXISTS uq_job_source_references_source_external")
    _rebuild_sources(connection, downgrade=True)
