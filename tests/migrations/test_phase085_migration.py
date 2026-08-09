"""F8.5 fresh/upgrade/downgrade smoke without provider network."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _alembic(database: Path, *arguments: str) -> None:
    environment = {**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"}
    subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=True,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )


def test_f85_direct_upgrade_and_empty_downgrade_round_trip(tmp_path: Path) -> None:
    database = tmp_path / "phase085.db"
    _alembic(database, "upgrade", "48213cabbd50")
    _alembic(database, "upgrade", "c35a9e7b1d44")
    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "acquisition_budget_periods",
            "acquisition_reservations",
            "provider_call_ledger",
            "discovery_query_memos",
        } <= tables
    _alembic(database, "downgrade", "48213cabbd50")
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "48213cabbd50",
        )
    _alembic(database, "upgrade", "c35a9e7b1d44")
