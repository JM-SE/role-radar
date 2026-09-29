"""Fresh/upgrade/downgrade guards for the feedback provenance columns."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
HEAD = "f13_feedback_provenance"
BASE = "f12_profile_first_mvp"

COLUMNS = (
    "profile_id",
    "row_version",
    "schema_version",
    "canonical_profile_sha256",
    "policy_hash",
    "relevance_version",
    "text_sha256",
    "reviewer",
)


def alembic(
    database: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=ROOT,
        env={**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"},
        check=check,
        capture_output=True,
        text=True,
    )


def version(database: Path) -> str:
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    if row is None or not isinstance(row[0], str):
        raise AssertionError("alembic version row is missing or invalid")
    return row[0]


def columns(database: Path) -> set[str]:
    with sqlite3.connect(database) as connection:
        rows = connection.execute("PRAGMA table_info(feedback_decisions)").fetchall()
    return {row[1] for row in rows}


def test_provenance_upgrade_adds_columns_and_clean_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "provenance.db"
    alembic(database, "upgrade", HEAD)
    assert version(database) == HEAD
    assert set(COLUMNS) <= columns(database)
    alembic(database, "downgrade", BASE)
    assert version(database) == BASE
    assert not (set(COLUMNS) & columns(database))
    alembic(database, "upgrade", HEAD)
    assert version(database) == HEAD
    assert set(COLUMNS) <= columns(database)
