"""Fresh/upgrade/downgrade and identity-collision guards for F10.1B."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
BASE = "e7a4c9f1b2d3"
HEAD = "f101b_continuous"


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


def test_fresh_upgrade_from_f87_and_clean_downgrade(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.db"
    alembic(fresh, "upgrade", "head")
    assert version(fresh) == HEAD

    with sqlite3.connect(fresh) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert {"source_discovery_runs", "continuous_acquisition_runs", "job_identity_keys"} <= tables

    upgraded = tmp_path / "upgraded.db"
    alembic(upgraded, "upgrade", BASE)
    alembic(upgraded, "upgrade", HEAD)
    assert version(upgraded) == HEAD
    alembic(upgraded, "downgrade", BASE)
    assert version(upgraded) == BASE
    with sqlite3.connect(upgraded) as connection:
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name='job_identity_keys'"
            ).fetchone()
            is None
        )


def test_upgrade_refuses_ambiguous_identity_backfill(tmp_path: Path) -> None:
    database = tmp_path / "collision.db"
    alembic(database, "upgrade", BASE)
    with sqlite3.connect(database) as connection:
        # F8.1 normally prevents this state. Remove that guard to exercise the
        # F10.1B backfill's own collision refusal in isolation.
        connection.execute("DROP INDEX uq_job_source_references_source_external")
        connection.execute(
            "INSERT INTO sources (id,type,name,configuration,enabled,source_key,"
            "configuration_version,revision,updated_at,created_at,management_origin) "
            "VALUES ('source-1','greenhouse','Acme','{}',1,'greenhouse:acme',1,1,"
            "datetime('now'),datetime('now'),'manual')"
        )
        for job_id in ("job-1", "job-2"):
            connection.execute(
                "INSERT INTO jobs (id,title,company,status,first_seen_at,last_seen_at,"
                "created_at,updated_at) "
                "VALUES (?, 'Engineer', 'Acme', 'new', datetime('now'),"
                "datetime('now'),datetime('now'),datetime('now'))",
                (job_id,),
            )
            connection.execute(
                "INSERT INTO job_source_references (id,job_id,source_id,external_id,collected_at) "
                "VALUES (?, ?, 'source-1', 'same-external-id', datetime('now'))",
                (f"ref-{job_id}", job_id),
            )
        connection.commit()

    failed = alembic(database, "upgrade", HEAD, check=False)
    assert failed.returncode != 0
    assert version(database) == BASE
