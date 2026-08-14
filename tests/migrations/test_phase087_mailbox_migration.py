"""F8.7 migration fresh/upgrade/downgrade and durable-activity guard."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _alembic(
    database: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=check,
        cwd=ROOT,
        env={**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"},
        capture_output=True,
        text=True,
    )


def test_fresh_and_f86_upgrade_create_mailbox_tables(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.db"
    _alembic(fresh, "upgrade", "e7a4c9f1b2d3")
    upgraded = tmp_path / "upgrade.db"
    _alembic(upgraded, "upgrade", "d8f6a1b2c3d4")
    _alembic(upgraded, "upgrade", "e7a4c9f1b2d3")
    for database in (fresh, upgraded):
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
                "e7a4c9f1b2d3",
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            assert {"mailbox_states", "email_receipts", "email_link_proposals"} <= tables


def test_clean_downgrade_and_activity_guard(tmp_path: Path) -> None:
    clean = tmp_path / "clean.db"
    _alembic(clean, "upgrade", "e7a4c9f1b2d3")
    _alembic(clean, "downgrade", "d8f6a1b2c3d4")
    with sqlite3.connect(clean) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name='email_receipts'"
        ).fetchone() is None

    active = tmp_path / "active.db"
    _alembic(active, "upgrade", "e7a4c9f1b2d3")
    with sqlite3.connect(active) as connection:
        connection.execute(
            "INSERT INTO email_receipts "
            "(id,source_id,uidvalidity,uid,status,created_at) "
            "VALUES ('receipt','source',1,1,'review',datetime('now'))"
        )
        connection.commit()
    failed = _alembic(active, "downgrade", "d8f6a1b2c3d4", check=False)
    assert failed.returncode != 0
