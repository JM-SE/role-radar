import os
import sqlite3
import subprocess
import sys
from pathlib import Path


def _alembic(database: Path, *arguments: str) -> None:
    environment = {**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"}
    subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=True,
        cwd=Path(__file__).parents[2],
        env=environment,
        capture_output=True,
        text=True,
    )


def test_aa04_adds_persisted_canary_budget_and_checkpoint_from_aa03(tmp_path: Path) -> None:
    database = tmp_path / "canary.db"
    _alembic(database, "upgrade", "aa03_reconcile_legacy_campaign_schema")

    with sqlite3.connect(database) as connection:
        assert connection.execute("select version_num from alembic_version").fetchone() == (
            "aa03_reconcile_legacy_campaign_schema",
        )

    _alembic(database, "upgrade", "head")
    with sqlite3.connect(database) as connection:
        column_info = {
            row[1]: (row[2].upper(), row[3])
            for row in connection.execute("pragma table_info(job_search_runs)")
        }
        revision = connection.execute("select version_num from alembic_version").fetchone()
        table_ddl = connection.execute(
            "select sql from sqlite_master where type='table' and name='job_search_runs'"
        ).fetchone()[0]

    assert revision == ("aa04_bounded_canary_execution",)
    assert column_info["canary_budget_json"] == ("JSON", 0)
    assert column_info["canary_checkpoint_json"] == ("JSON", 0)
    assert "check (status" not in table_ddl.lower()
