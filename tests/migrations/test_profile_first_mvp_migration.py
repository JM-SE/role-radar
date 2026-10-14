"""Fresh/upgrade guards for nullable preliminary-only notification items."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
HEAD = "f12_profile_first_mvp"
BASE = "f11_feedback"


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


def test_profile_first_nullable_upgrade_preserves_rows(tmp_path: Path) -> None:
    database = tmp_path / "profile-first.db"
    alembic(database, "upgrade", HEAD)
    assert version(database) == HEAD
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='notification_items'"
        ).fetchone()
        assert row is not None
        assert "uq_notification_items_global_job" in row[0]


def test_profile_first_upgrade_from_feedback_head(tmp_path: Path) -> None:
    database = tmp_path / "upgraded.db"
    alembic(database, "upgrade", BASE)
    alembic(database, "upgrade", HEAD)
    assert version(database) == HEAD
