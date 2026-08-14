"""F8.6 poll-state migration: fresh, upgrade, downgrade, and activity guard."""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _alembic(
    database: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=check,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )


def test_fresh_and_f85_upgrade_create_poll_state(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.db"
    _alembic(fresh, "upgrade", "e7a4c9f1b2d3")
    with sqlite3.connect(fresh) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone() == (
            "e7a4c9f1b2d3",
        )
        assert connection.execute("SELECT COUNT(*) FROM source_poll_states").fetchone() == (0,)

    upgraded = tmp_path / "from-f85.db"
    _alembic(upgraded, "upgrade", "c35a9e7b1d44")
    with sqlite3.connect(upgraded) as connection:
        connection.execute(
            "INSERT INTO sources "
            "(id,type,name,configuration,enabled,source_key,configuration_version,revision,"
            "created_at,updated_at) "
            "VALUES ('source-1','jobicy','Jobicy',?,0,'jobicy:latam',1,1,"
            "datetime('now'),datetime('now'))",
            ('{"region":"latam","remote_only":true}',),
        )
        connection.commit()
    _alembic(upgraded, "upgrade", "e7a4c9f1b2d3")
    with sqlite3.connect(upgraded) as connection:
        assert connection.execute(
            "SELECT source_id, cadence_version, policy_version, revision "
            "FROM source_poll_states"
        ).fetchone() == ("source-1", "jobicy-hourly-v1", "jobicy-latam-v1", 1)


def test_clean_downgrade_removes_state_and_activity_downgrade_fails(tmp_path: Path) -> None:
    clean = tmp_path / "clean.db"
    _alembic(clean, "upgrade", "e7a4c9f1b2d3")
    _alembic(clean, "downgrade", "c35a9e7b1d44")
    with sqlite3.connect(clean) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE name='source_poll_states'"
        ).fetchone() is None

    active = tmp_path / "active.db"
    _alembic(active, "upgrade", "e7a4c9f1b2d3")
    with sqlite3.connect(active) as connection:
        connection.execute(
            "INSERT INTO source_poll_states "
            "(id,source_id,cadence_version,policy_version,next_due_at,revision,"
            "created_at,updated_at) "
            "VALUES ('poll-1','source-1','jobicy-hourly-v1','jobicy-latam-v1',"
            "datetime('now'),1,datetime('now'),datetime('now'))"
        )
        connection.execute(
            "UPDATE source_poll_states SET last_request_at=datetime('now')"
        )
        connection.commit()
    failed = _alembic(active, "downgrade", "c35a9e7b1d44", check=False)
    assert failed.returncode != 0
