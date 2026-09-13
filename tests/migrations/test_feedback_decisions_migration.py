"""Fresh/upgrade/downgrade guards for the feedback decisions table."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
HEAD = "f11_feedback"
BASE = "f101b_continuous"


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


def test_feedback_table_upgrade_and_clean_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "feedback.db"
    alembic(database, "upgrade", BASE)
    alembic(database, "upgrade", HEAD)
    assert version(database) == HEAD
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE name='feedback_decisions'"
        ).fetchone()
    assert row is not None
    alembic(database, "downgrade", BASE)
    assert version(database) == BASE
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='feedback_decisions'"
            ).fetchone()
            is None
        )
