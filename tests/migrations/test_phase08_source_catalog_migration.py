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


def test_fresh_and_f7_upgrade_downgrade_smoke(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.db"
    _alembic(fresh, "upgrade", "e7a4c9f1b2d3")
    with sqlite3.connect(fresh) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "e7a4c9f1b2d3",
        )

    upgraded = tmp_path / "f7.db"
    _alembic(upgraded, "upgrade", "7f0a4c2d9e11")
    with sqlite3.connect(upgraded) as connection:
        connection.execute(
            "INSERT INTO sources "
            "(id,type,name,configuration,enabled,created_at) "
            "VALUES ('s1','greenhouse','A',? ,0,datetime('now'))",
            ('{"board_token":" Acme "}',),
        )
        connection.commit()
    _alembic(upgraded, "upgrade", "e7a4c9f1b2d3")
    with sqlite3.connect(upgraded) as connection:
        assert connection.execute(
            "SELECT source_key, configuration_version, enabled FROM sources"
        ).fetchone() == ("greenhouse:acme", 1, 0)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_poll_states"
        ).fetchone() == (1,)
    _alembic(upgraded, "downgrade", "7f0a4c2d9e11")
