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
HEAD = "aa03_reconcile_legacy_campaign_schema"


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


def test_upgrade_reconciles_populated_legacy_activation_schema(tmp_path: Path) -> None:
    database = tmp_path / "legacy-activation.db"
    alembic(database, "upgrade", "aa02_run_clarification_budget")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TABLE source_activation_members")
        connection.execute("DROP TABLE source_activation_campaigns")
        connection.execute(
            """CREATE TABLE source_activation_campaigns (
                id VARCHAR(36) PRIMARY KEY,
                profile_id VARCHAR(36) NOT NULL REFERENCES candidate_profiles(id)
                    ON DELETE RESTRICT,
                status VARCHAR(16) NOT NULL DEFAULT 'active',
                batch_size INTEGER NOT NULL CHECK (batch_size > 0),
                max_failure_streak INTEGER NOT NULL,
                max_no_signal_streak INTEGER NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                CHECK (status IN ('active','paused','completed')),
                CONSTRAINT ck_activation_campaign_failure_limit
                    CHECK (max_failure_streak > 0),
                CONSTRAINT ck_activation_campaign_signal_limit
                    CHECK (max_no_signal_streak > 0)
            )"""
        )
        connection.execute(
            """CREATE TABLE legacy_members (
                id VARCHAR(36) PRIMARY KEY,
                campaign_id VARCHAR(36) NOT NULL REFERENCES source_activation_campaigns(id)
                    ON DELETE CASCADE,
                source_id VARCHAR(36) NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
                role VARCHAR(16) NOT NULL CHECK (role IN ('baseline','managed')),
                ordinal INTEGER NOT NULL,
                state VARCHAR(24) NOT NULL DEFAULT 'pending',
                failure_streak INTEGER NOT NULL DEFAULT 0 CHECK (failure_streak >= 0),
                no_signal_streak INTEGER NOT NULL DEFAULT 0 CHECK (no_signal_streak >= 0),
                last_selected_at DATETIME,
                last_run_id VARCHAR(36) REFERENCES job_search_runs(id) ON DELETE SET NULL,
                CONSTRAINT ck_activation_member_state
                    CHECK (state IN ('pending','retained','disabled_failure','disabled_no_signal')),
                UNIQUE(campaign_id,source_id), UNIQUE(campaign_id,ordinal)
            )"""
        )
        connection.execute(
            """INSERT INTO candidate_profiles
               (id,name,version,schema_version,profile_json,is_active,created_at,updated_at)
               VALUES ('legacy-profile','profile',1,1,'{}',1,'2026-09-01','2026-09-01')"""
        )
        for ordinal in range(4):
            connection.execute(
                """INSERT INTO sources
                   (id,type,name,configuration,enabled,created_at,source_key,
                    configuration_version,revision,updated_at,management_origin,archived_at)
                   VALUES (?,?,?,?,?,'2026-09-01',?,1,1,'2026-09-01','manual',NULL)""",
                (f'legacy-source-{ordinal}', 'greenhouse', 'Acme', '{}', 0,
                 f'greenhouse:legacy-{ordinal}'),
            )
        connection.execute(
            """INSERT INTO job_search_runs
               (id,reason,status,created_at,updated_at,request_hash,recovery_count,
                notification_mode,discovery_mode,profile_id)
               VALUES ('legacy-run','legacy-run','completed','2026-09-01','2026-09-01',
                       '',0,'none','none','legacy-profile')"""
        )
        connection.execute(
            """INSERT INTO source_activation_campaigns
               (id,profile_id,batch_size,max_failure_streak,max_no_signal_streak,created_at,updated_at)
               VALUES ('legacy-campaign','legacy-profile',20,3,4,'2026-09-01','2026-09-01')"""
        )
        campaign_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='source_activation_campaigns'"
        ).fetchone()[0]
        assert 'CONSTRAINT ck_activation_campaign_failure_limit' in campaign_sql
        assert 'CONSTRAINT ck_activation_campaign_signal_limit' in campaign_sql
        connection.execute("ALTER TABLE legacy_members RENAME TO source_activation_members")
        for ordinal, state in enumerate(
            ('pending', 'retained', 'disabled_failure', 'disabled_no_signal')
        ):
            connection.execute(
                """INSERT INTO source_activation_members
                   (id,campaign_id,source_id,role,ordinal,state,failure_streak,no_signal_streak,last_run_id)
                   VALUES (?,?,?,'managed',?,?,0,0,?)""",
                (f'legacy-member-{ordinal}', 'legacy-campaign', f'legacy-source-{ordinal}',
                 ordinal, state, 'legacy-run' if ordinal == 0 else None),
            )
        connection.execute(
            "UPDATE job_search_runs SET activation_campaign_id='legacy-campaign' "
            "WHERE id='legacy-run'"
        )
        connection.commit()

    alembic(database, "upgrade", HEAD)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        assert connection.execute(
            "SELECT id,enabled,archived_at FROM sources WHERE id='legacy-source-0'"
        ).fetchone() == ('legacy-source-0', 0, None)
        assert connection.execute(
            "SELECT id FROM candidate_profiles WHERE id='legacy-profile'"
        ).fetchone() == ('legacy-profile',)
        assert connection.execute(
            "SELECT id,activation_campaign_id FROM job_search_runs WHERE id='legacy-run'"
        ).fetchone() == ('legacy-run', 'legacy-campaign')
        assert connection.execute(
            "SELECT id FROM source_activation_campaigns WHERE id='legacy-campaign'"
        ).fetchone() == ('legacy-campaign',)
        assert connection.execute(
            "SELECT id FROM sources ORDER BY id"
        ).fetchall() == [(f'legacy-source-{i}',) for i in range(4)]
        assert connection.execute(
            "SELECT count(*) FROM sources WHERE enabled=0 AND archived_at IS NULL"
        ).fetchone() == (4,)
        assert connection.execute(
            "SELECT id,last_run_id FROM source_activation_members WHERE ordinal=0"
        ).fetchone() == ('legacy-member-0', 'legacy-run')
        assert connection.execute(
            "SELECT id,state FROM source_activation_members ORDER BY ordinal"
        ).fetchall() == [
            ('legacy-member-0', 'pending'),
            ('legacy-member-1', 'retained'),
            ('legacy-member-2', 'retained'),
            ('legacy-member-3', 'retained'),
        ]
        assert connection.execute(
            "SELECT state,count(*) FROM source_activation_members GROUP BY state ORDER BY state"
        ).fetchall() == [('pending', 1), ('retained', 3)]
        assert connection.execute(
            "SELECT count(*) FROM source_activation_members"
        ).fetchone() == (4,)
        campaign_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='source_activation_campaigns'"
        ).fetchone()[0]
        assert 'max_failure_streak' not in campaign_sql
        assert 'max_no_signal_streak' not in campaign_sql
        connection.execute(
            """INSERT INTO source_activation_campaigns
               (id,profile_id,status,batch_size,created_at,updated_at)
               VALUES ('new-campaign','legacy-profile','active',20,'2026-09-02','2026-09-02')"""
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE source_activation_members SET state='disabled_failure' "
                "WHERE id='legacy-member-0'"
            )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
