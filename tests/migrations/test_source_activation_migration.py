"""The F2 campaign schema rebuild preserves prior run/profile/source rows."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
BASE = "f11_feedback"
HEAD = "aa02_run_clarification_budget"


def alembic(database: Path, *arguments: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=ROOT,
        env={**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"},
        check=True,
        capture_output=True,
        text=True,
    )


def test_upgrade_from_feedback_head_preserves_rows_and_campaign_constraints(
    tmp_path: Path,
) -> None:
    database = tmp_path / "activation-upgrade.db"
    alembic(database, "upgrade", BASE)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            """INSERT INTO candidate_profiles
               (id,name,version,schema_version,profile_json,is_active,created_at,updated_at)
               VALUES ('profile-old','profile',1,1,'{}',1,'2026-09-01','2026-09-01')"""
        )
        connection.execute(
            """INSERT INTO sources
               (id,type,name,configuration,enabled,created_at,source_key,
                configuration_version,revision,updated_at,management_origin)
               VALUES ('source-old','greenhouse','Acme','{}',1,'2026-09-01',
                       'greenhouse:acme',1,1,'2026-09-01','manual')"""
        )
        connection.execute(
            """INSERT INTO job_search_runs
               (id,reason,status,created_at,updated_at,request_hash,recovery_count,
                notification_mode,discovery_mode,profile_id)
               VALUES ('run-old','existing-run','completed','2026-09-01','2026-09-01',
                       '',0,'none','none','profile-old')"""
        )

    alembic(database, "upgrade", HEAD)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        assert version == (HEAD,)
        assert connection.execute(
            "SELECT id, reason FROM job_search_runs WHERE id='run-old'"
        ).fetchone() == ("run-old", "existing-run")
        assert connection.execute(
            "SELECT id, source_key FROM sources WHERE id='source-old'"
        ).fetchone() == ("source-old", "greenhouse:acme")
        assert connection.execute(
            "SELECT id, version FROM candidate_profiles WHERE id='profile-old'"
        ).fetchone() == ("profile-old", 1)
        assert connection.execute(
            "SELECT clarification_attempts FROM job_search_runs WHERE id='run-old'"
        ).fetchone() == (0,)

        connection.execute(
            """INSERT INTO source_activation_campaigns
               (id,profile_id,status,batch_size,created_at,updated_at)
               VALUES ('campaign-new','profile-old','active',20,'2026-09-02','2026-09-02')"""
        )
        connection.execute(
            """INSERT INTO source_activation_members
               (id,campaign_id,source_id,role,ordinal,state,failure_streak,no_signal_streak)
               VALUES ('member-new','campaign-new','source-old','managed',0,'pending',0,0)"""
        )
        member_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='source_activation_members'"
        ).fetchone()[0]
        assert "state IN ('pending','retained')" in member_sql
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE source_activation_members SET state='disabled_failure' "
                "WHERE id='member-new'"
            )
        connection.execute(
            "UPDATE job_search_runs SET activation_campaign_id='campaign-new' WHERE id='run-old'"
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        run_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='job_search_runs'"
        ).fetchone()[0]
        assert "ck_job_search_runs_clarification_attempts" in run_sql
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE job_search_runs SET clarification_attempts=-1 WHERE id='run-old'"
            )
