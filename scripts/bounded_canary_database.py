#!/usr/bin/env python3
"""Bounded read-only SQLite history gate for canary operations."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
import time
from contextlib import suppress
from pathlib import Path
from urllib.parse import quote

DEFAULT_DATABASE_URL = "sqlite:///./data/role-radar.db"
REVISION = "aa04_bounded_canary_execution"
LOCATION_UNCONFIRMED_REVISION = "aa05_location_unconfirmed"
SUPPORTED_REVISIONS = {REVISION, LOCATION_UNCONFIRMED_REVISION}
_LOCATION_UNCONFIRMED_SCHEMA_SQL = """
CREATE TABLE location_unconfirmed (
    id VARCHAR(36) NOT NULL,
    profile_id VARCHAR(36) NOT NULL,
    profile_version INTEGER NOT NULL,
    profile_schema_version INTEGER NOT NULL,
    profile_hash VARCHAR(64) NOT NULL,
    source_id VARCHAR(36) NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    company VARCHAR(255) NOT NULL,
    location VARCHAR(255),
    source_url VARCHAR(2048),
    application_url VARCHAR(2048) NOT NULL,
    reason_code VARCHAR(32) NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT ck_location_unconfirmed_profile_version CHECK (profile_version > 0),
    CONSTRAINT ck_location_unconfirmed_profile_schema_version CHECK (profile_schema_version > 0),
    CONSTRAINT ck_location_unconfirmed_profile_hash_length CHECK (length(profile_hash) = 64),
    CONSTRAINT ck_location_unconfirmed_external_id CHECK (length(trim(external_id)) > 0),
    CONSTRAINT ck_location_unconfirmed_title CHECK (length(trim(title)) > 0),
    CONSTRAINT ck_location_unconfirmed_company CHECK (length(trim(company)) > 0),
    CONSTRAINT ck_location_unconfirmed_application_url CHECK (length(trim(application_url)) > 0),
    CONSTRAINT ck_location_unconfirmed_reason_code CHECK (reason_code = 'region_unknown'),
    CONSTRAINT fk_location_unconfirmed_profile
        FOREIGN KEY(profile_id) REFERENCES candidate_profiles (id) ON DELETE CASCADE,
    CONSTRAINT fk_location_unconfirmed_source
        FOREIGN KEY(source_id) REFERENCES sources (id) ON DELETE RESTRICT,
    CONSTRAINT uq_location_unconfirmed_profile_source_external
        UNIQUE (profile_id, source_id, external_id)
)
"""
LOCATION_UNCONFIRMED_SCHEMA_SQL = " ".join(_LOCATION_UNCONFIRMED_SCHEMA_SQL.split())
RUN_COLUMNS = (
    "id, status, profile_id, started_at, completed_at, claimed_by, "
    "lease_expires_at, heartbeat_at, recovery_count"
)
RUN_STATUSES = {
    "pending",
    "collecting",
    "normalizing",
    "extracting",
    "scoring",
    "deep_evaluating",
    "notifying",
    "deferred",
    "completed",
    "failed",
    "cancelled",
}
ACTIVE_RUN_STATUSES = RUN_STATUSES - {"deferred", "completed", "failed", "cancelled"}
BATCH_STATUSES = {"pending", "prepared", "sending", "retry_wait", "sent", "failed", "unknown"}
ITEM_STATUSES = {"reserved", "sent", "failed", "unknown"}
UNRESOLVED_BATCH_STATUSES = {"pending", "prepared", "sending", "retry_wait", "unknown"}
UNRESOLVED_ITEM_STATUSES = {"reserved", "unknown"}
REQUIRED_COLUMNS = {
    "alembic_version": {"version_num"},
    "job_search_runs": set(RUN_COLUMNS.replace(" ", "").split(","))
    | {"canary_budget_json", "canary_checkpoint_json"},
    "notification_batches": {"id", "run_id", "status"},
    "notification_items": {"id", "batch_id", "run_id", "status"},
}


class GateError(Exception):
    """A fixed, privacy-safe public gate failure."""


class _ReadOnlyConnection(sqlite3.Connection):
    target_path: Path
    target_identity: tuple[int, ...]


def _database_url_path(database_url: str) -> str:
    if not database_url.startswith("sqlite:///"):
        raise GateError("database_target_invalid")
    raw_path = database_url.removeprefix("sqlite:///")
    if not raw_path or raw_path.startswith("//") or "?" in raw_path or "#" in raw_path:
        raise GateError("database_target_invalid")
    if "\0" in raw_path:
        raise GateError("database_target_invalid")
    return raw_path


def _database_path(database_url: str) -> Path:
    raw_path = _database_url_path(database_url)
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    # Reject symlinks in every existing path component before resolving the target.
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        try:
            if cursor.is_symlink():
                raise GateError("database_target_invalid")
        except OSError:
            raise GateError("database_unavailable") from None
    try:
        return candidate.resolve(strict=True)
    except OSError:
        raise GateError("database_unavailable") from None


def _file_identity(path: Path) -> tuple[int, ...]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise GateError("database_target_unavailable")
    descriptor = None
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise GateError("database_target_invalid")
        descriptor = os.open(path, os.O_RDONLY | nofollow | os.O_NONBLOCK)
        opened = os.fstat(descriptor)
        header = os.read(descriptor, 20)
        after = os.fstat(descriptor)
        path_after = path.stat(follow_symlinks=False)
    except GateError:
        raise
    except OSError:
        raise GateError("database_unavailable") from None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    states = (before, opened, after, path_after)

    def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if (
        any(not stat.S_ISREG(item.st_mode) for item in states)
        or len({identity(item) for item in states}) != 1
    ):
        raise GateError("database_target_changed")
    sqlite_magic = bytes.fromhex("53514c69746520666f726d6174203300")
    if header[:16] != sqlite_magic or header[18:20] not in {bytes((1, 1)), bytes((2, 2))}:
        raise GateError("database_schema_unavailable")
    return (*identity(before), int(header[18:20] == bytes((2, 2))))


def _require_wal_resources(path: Path, identity: tuple[int, ...]) -> None:
    wal_mode = identity[-1] == 1
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        try:
            sidecar_info = sidecar.lstat()
        except FileNotFoundError:
            if wal_mode and suffix in {"-wal", "-shm"}:
                raise GateError("database_wal_resources_unavailable") from None
            continue
        except OSError:
            raise GateError("database_wal_resources_unavailable") from None
        if suffix == "-journal" or not stat.S_ISREG(sidecar_info.st_mode):
            raise GateError("database_wal_resources_unavailable")
        if not wal_mode:
            raise GateError("database_wal_resources_unavailable")


def _connect_database(database_url: str) -> sqlite3.Connection:
    path = _database_path(database_url)
    identity = _file_identity(path)
    _require_wal_resources(path, identity)
    uri = f"file:{quote(str(path), safe='/')}?mode=ro"
    deadline = time.monotonic() + 1.0
    connection = None
    try:
        connection = sqlite3.connect(
            uri, uri=True, timeout=1.0, isolation_level=None, factory=_ReadOnlyConnection
        )
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.execute("PRAGMA busy_timeout=1000")
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        if _file_identity(path) != identity:
            raise GateError("database_target_changed")
        connection.target_path = path
        connection.target_identity = identity
        return connection
    except Exception as exc:
        if connection is not None:
            with suppress(Exception):
                connection.close()
        if isinstance(exc, GateError):
            raise
        raise GateError("database_unavailable") from None


def _rows(connection: sqlite3.Connection, query: str) -> tuple[tuple, ...]:
    try:
        return tuple(connection.execute(query).fetchall())
    except sqlite3.Error:
        raise GateError("schema_invalid") from None


def _validate_location_unconfirmed_schema(connection: sqlite3.Connection, tables: set[str]) -> None:
    required_tables = {"candidate_profiles", "sources", "location_unconfirmed"}
    if not required_tables <= tables:
        raise GateError("schema_invalid")

    expected_columns = {
        "id": ("VARCHAR(36)", 1, 1),
        "profile_id": ("VARCHAR(36)", 1, 0),
        "profile_version": ("INTEGER", 1, 0),
        "profile_schema_version": ("INTEGER", 1, 0),
        "profile_hash": ("VARCHAR(64)", 1, 0),
        "source_id": ("VARCHAR(36)", 1, 0),
        "external_id": ("VARCHAR(255)", 1, 0),
        "title": ("VARCHAR(255)", 1, 0),
        "company": ("VARCHAR(255)", 1, 0),
        "location": ("VARCHAR(255)", 0, 0),
        "source_url": ("VARCHAR(2048)", 0, 0),
        "application_url": ("VARCHAR(2048)", 1, 0),
        "reason_code": ("VARCHAR(32)", 1, 0),
        "first_seen_at": ("DATETIME", 1, 0),
        "last_seen_at": ("DATETIME", 1, 0),
    }
    column_rows = _rows(connection, 'PRAGMA table_info("location_unconfirmed")')
    actual_columns = {
        row[1]: (str(row[2]).upper(), int(row[3]), int(row[5])) for row in column_rows
    }
    if actual_columns != expected_columns:
        raise GateError("schema_invalid")

    foreign_keys = {
        (row[2], row[3], row[4], str(row[6]).upper())
        for row in _rows(connection, 'PRAGMA foreign_key_list("location_unconfirmed")')
    }
    if foreign_keys != {
        ("candidate_profiles", "profile_id", "id", "CASCADE"),
        ("sources", "source_id", "id", "RESTRICT"),
    }:
        raise GateError("schema_invalid")

    index_rows = _rows(connection, 'PRAGMA index_list("location_unconfirmed")')
    unique_indexes: set[tuple[str, ...]] = set()
    nonunique_indexes: dict[str, tuple[str, ...]] = {}
    for index_row in index_rows:
        name = str(index_row[1])
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise GateError("schema_invalid")
        index_columns = tuple(
            str(row[2]) for row in _rows(connection, f'PRAGMA index_info("{name}")')
        )
        if len(index_row) < 5 or int(index_row[4]) != 0:
            raise GateError("schema_invalid")
        if int(index_row[2]):
            unique_indexes.add(index_columns)
        else:
            nonunique_indexes[name] = index_columns
    if unique_indexes != {("id",), ("profile_id", "source_id", "external_id")}:
        raise GateError("schema_invalid")
    if nonunique_indexes != {
        "ix_location_unconfirmed_profile_binding_last_seen": (
            "profile_id",
            "profile_version",
            "profile_schema_version",
            "profile_hash",
            "last_seen_at",
        )
    }:
        raise GateError("schema_invalid")

    table_sql_rows = _rows(
        connection,
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='location_unconfirmed'",
    )
    if len(table_sql_rows) != 1 or not isinstance(table_sql_rows[0][0], str):
        raise GateError("schema_invalid")
    _validate_location_unconfirmed_table_sql(table_sql_rows[0][0])


def _validate_location_unconfirmed_table_sql(table_sql: str) -> None:
    """Require the exact aa05 table contract, not a finite sample of CHECK cases."""
    if " ".join(table_sql.split()) != LOCATION_UNCONFIRMED_SCHEMA_SQL:
        raise GateError("schema_invalid")


def _validate_schema(connection: sqlite3.Connection) -> None:
    tables = {
        row[0]
        for row in _rows(
            connection,
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )
    }
    if not set(REQUIRED_COLUMNS) <= tables:
        raise GateError("schema_invalid")
    for table, required in REQUIRED_COLUMNS.items():
        # Table identifiers come exclusively from the fixed map above.
        columns = {row[1] for row in _rows(connection, f'PRAGMA table_info("{table}")')}
        if not required <= columns:
            raise GateError("schema_invalid")
    versions = _rows(connection, "SELECT version_num FROM alembic_version")
    if len(versions) != 1 or versions[0][0] not in SUPPORTED_REVISIONS:
        raise GateError("schema_revision_invalid")
    revision = versions[0][0]
    if revision == REVISION:
        if "location_unconfirmed" in tables:
            raise GateError("schema_invalid")
    else:
        _validate_location_unconfirmed_schema(connection, tables)


def snapshot_history(connection: sqlite3.Connection) -> dict[str, tuple[dict, ...]]:
    """Internal metadata snapshot; deliberately excludes all payload-bearing columns."""
    runs = tuple(
        dict(zip(RUN_COLUMNS.replace(" ", "").split(","), row, strict=True))
        for row in _rows(connection, f"SELECT {RUN_COLUMNS} FROM job_search_runs ORDER BY id")
    )
    batches = tuple(
        dict(zip(("id", "run_id", "status"), row, strict=True))
        for row in _rows(
            connection, "SELECT id, run_id, status FROM notification_batches ORDER BY id"
        )
    )
    items = tuple(
        dict(zip(("id", "batch_id", "run_id", "status"), row, strict=True))
        for row in _rows(
            connection, "SELECT id, batch_id, run_id, status FROM notification_items ORDER BY id"
        )
    )
    return {"runs": runs, "batches": batches, "items": items}


def _public_snapshot_summary(snapshot: dict[str, tuple[dict, ...]]) -> str:
    """No record values leave the internal comparison API."""
    return json.dumps({key: len(rows) for key, rows in snapshot.items()}, sort_keys=True)


def _validate_history(snapshot: dict[str, tuple[dict, ...]]) -> None:
    for run in snapshot["runs"]:
        status = run["status"]
        if status not in RUN_STATUSES:
            raise GateError("run_history_unresolved")
        owned = run["claimed_by"] is not None or run["lease_expires_at"] is not None
        if status in ACTIVE_RUN_STATUSES or owned:
            raise GateError("run_history_unresolved")
    for batch in snapshot["batches"]:
        if batch["status"] not in BATCH_STATUSES or batch["status"] in UNRESOLVED_BATCH_STATUSES:
            raise GateError("outbox_unresolved")
    for item in snapshot["items"]:
        if item["status"] not in ITEM_STATUSES or item["status"] in UNRESOLVED_ITEM_STATUSES:
            raise GateError("outbox_unresolved")


def _inspect(connection: sqlite3.Connection) -> None:
    try:
        if connection.execute("PRAGMA query_only").fetchone() != (1,):
            raise GateError("database_readonly_unavailable")
        _validate_schema(connection)
        if _rows(connection, "PRAGMA integrity_check") != (("ok",),):
            raise GateError("database_integrity_invalid")
        if _rows(connection, "PRAGMA foreign_key_check"):
            raise GateError("database_foreign_key_invalid")
        snapshot = snapshot_history(connection)
        _validate_history(snapshot)
    except sqlite3.Error:
        raise GateError("database_inspection_unavailable") from None


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise GateError("arguments_invalid")


def _reject_repeated_database_url(argv: list[str] | None) -> None:
    tokens = sys.argv[1:] if argv is None else argv
    occurrences = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--database-url" or token.startswith("--database-url="):
            occurrences += 1
            if occurrences > 1:
                raise GateError("arguments_invalid")
            if token == "--database-url":
                index += 1
        index += 1


def _verify_target_stable(connection: sqlite3.Connection) -> None:
    if isinstance(connection, _ReadOnlyConnection):
        if _file_identity(connection.target_path) != connection.target_identity:
            raise GateError("database_target_changed")
        _require_wal_resources(connection.target_path, connection.target_identity)


def main(argv: list[str] | None = None) -> int:
    connection = None
    failure = None
    try:
        _reject_repeated_database_url(argv)
        parser = _SafeArgumentParser(
            description="Read-only SQLite canary history gate only.", allow_abbrev=False
        )
        parser.add_argument(
            "--database-url",
            default=DEFAULT_DATABASE_URL,
            help="SQLite file URL; relative paths resolve from the current directory",
        )
        args = parser.parse_args(argv)
        _database_url_path(args.database_url)
        connection = _connect_database(args.database_url)
        _inspect(connection)
        _verify_target_stable(connection)
    except GateError as exc:
        failure = str(exc)
    except Exception:
        failure = "database_inspection_unavailable"
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                failure = "database_inspection_unavailable"
    if failure is not None:
        print(f"DATABASE_HISTORY_GATE: FAIL ({failure})", file=sys.stderr)
        return 1
    print("DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
