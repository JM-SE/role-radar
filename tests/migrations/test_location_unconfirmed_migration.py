from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from role_radar.domain.enums import SourceType
from role_radar.domain.profile import CandidateProfileV1
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.sources import SourceRepository
from scripts import bounded_canary_database as database_gate

ROOT = Path(__file__).resolve().parents[2]
AA04 = "aa04_bounded_canary_execution"
AA05 = "aa05_location_unconfirmed"


def _alembic(database: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "ROLE_RADAR_DATABASE_URL": f"sqlite:///{database}"}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        check=False,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )


def _profile() -> dict[str, object]:
    return CandidateProfileV1.model_validate(
        {
            "title": None,
            "years_of_experience": None,
            "target_roles": ["frontend"],
            "target_titles": [],
            "core_skills": [],
            "secondary_skills": [],
            "regions": ["argentina"],
            "remote_only": True,
            "employment_preferences": [],
            "languages": {},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {
                "available_work_authorizations": ["argentina"],
                "unavailable_work_authorizations": [],
                "allowed_employment_types": [],
                "allowed_remote_policies": [],
            },
            "soft_preferences": {},
        }
    ).model_dump(mode="json")


def _upgrade_head(database: Path) -> None:
    result = _alembic(database, "upgrade", "head")
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_aa05_migration_creates_review_schema_from_aa04(tmp_path: Path) -> None:
    database = tmp_path / "location-review.db"
    result = _alembic(database, "upgrade", AA04)
    assert result.returncode == 0, (result.stdout, result.stderr)
    result = _alembic(database, "upgrade", "head")
    assert result.returncode == 0, (result.stdout, result.stderr)

    with sqlite3.connect(database) as connection:
        revision = connection.execute("select version_num from alembic_version").fetchone()
        assert revision == (AA05,)
        columns = {
            row[1]: (row[2].upper(), row[3], row[5])
            for row in connection.execute("pragma table_info(location_unconfirmed)")
        }
        foreign_keys = {
            (row[2], row[3], row[4], row[6])
            for row in connection.execute("pragma foreign_key_list(location_unconfirmed)")
        }
        index_rows = tuple(connection.execute("pragma index_list(location_unconfirmed)"))
        indexes = {row[1]: row[2] for row in index_rows}
        unique_index_columns = {
            tuple(row[2] for row in connection.execute(f'pragma index_info("{index_row[1]}")'))
            for index_row in index_rows
            if index_row[2] == 1
        }
        index_columns = tuple(
            row[2]
            for row in connection.execute(
                "pragma index_info(ix_location_unconfirmed_profile_binding_last_seen)"
            )
        )
        ddl = connection.execute(
            "select sql from sqlite_master where type='table' and name='location_unconfirmed'"
        ).fetchone()[0]

    assert " ".join(ddl.split()) == database_gate.LOCATION_UNCONFIRMED_SCHEMA_SQL
    normalized_ddl = " ".join(ddl.lower().split())
    assert columns == {
        "id": ("VARCHAR(36)", 1, 1),
        "profile_id": ("VARCHAR(36)", 1, 0),
        "profile_version": ("INTEGER", 1, 0),
        "profile_schema_version": ("INTEGER", 1, 0),
        "profile_hash": ("VARCHAR(64)", 1, 0),
        "source_id": ("VARCHAR(36)", 1, 0),
        "external_id": ("VARCHAR(255)", 1, 0),
        "title": ("VARCHAR(255)", 1, 0),
        "company": ("VARCHAR(255)", 1, 0),
        "location": ("VARCHAR(255)", 0, 0),
        "source_url": ("VARCHAR(2048)", 0, 0),
        "application_url": ("VARCHAR(2048)", 1, 0),
        "reason_code": ("VARCHAR(32)", 1, 0),
        "first_seen_at": ("DATETIME", 1, 0),
        "last_seen_at": ("DATETIME", 1, 0),
    }
    assert foreign_keys == {
        ("candidate_profiles", "profile_id", "id", "CASCADE"),
        ("sources", "source_id", "id", "RESTRICT"),
    }
    assert ("profile_id", "source_id", "external_id") in unique_index_columns
    assert indexes.get("ix_location_unconfirmed_profile_binding_last_seen") == 0
    assert index_columns == (
        "profile_id",
        "profile_version",
        "profile_schema_version",
        "profile_hash",
        "last_seen_at",
    )
    for check in (
        "check (profile_version > 0)",
        "check (profile_schema_version > 0)",
        "check (length(profile_hash) = 64)",
        "check (length(trim(external_id)) > 0)",
        "check (length(trim(title)) > 0)",
        "check (length(trim(company)) > 0)",
        "check (length(trim(application_url)) > 0)",
        "check (reason_code = 'region_unknown')",
    ):
        assert check in normalized_ddl


def test_aa05_migrated_database_passes_public_canary_gate(tmp_path: Path) -> None:
    database = tmp_path / "migrated-review.db"
    result = _alembic(database, "upgrade", AA04)
    assert result.returncode == 0, (result.stdout, result.stderr)
    result = _alembic(database, "upgrade", "head")
    assert result.returncode == 0, (result.stdout, result.stderr)
    before = database.read_bytes()

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/bounded_canary_database.py"),
            "--database-url",
            f"sqlite:///{database}",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n"
    assert result.stderr == ""
    assert database.read_bytes() == before
    assert not Path(f"{database}-wal").exists()
    assert not Path(f"{database}-shm").exists()


def test_aa05_empty_downgrade_removes_only_review_schema(tmp_path: Path) -> None:
    database = tmp_path / "empty-review.db"
    _upgrade_head(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("select version_num from alembic_version").fetchone() == (AA05,)
        assert (
            connection.execute(
                "select name from sqlite_master where type='table' and name='location_unconfirmed'"
            ).fetchone()
            is not None
        )

    result = _alembic(database, "downgrade", AA04)
    assert result.returncode == 0, (result.stdout, result.stderr)
    with sqlite3.connect(database) as connection:
        assert connection.execute("select version_num from alembic_version").fetchone() == (AA04,)
        assert (
            connection.execute(
                "select name from sqlite_master where type='table' and name='location_unconfirmed'"
            ).fetchone()
            is None
        )


def test_aa05_nonempty_downgrade_refuses_without_changing_review_data(
    tmp_path: Path,
) -> None:
    database = tmp_path / "populated-review.db"
    _upgrade_head(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("select version_num from alembic_version").fetchone() == (AA05,)

    engine = create_engine(f"sqlite:///{database}")
    with Session(engine) as session:
        profile = ProfileRepository(session).create_v1(
            name="review-profile", profile_json=_profile()
        )
        source = SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme"},
            enabled=True,
        )
        session.commit()
        session.execute(
            text(
                "INSERT INTO location_unconfirmed "
                "(id, profile_id, profile_version, profile_schema_version, profile_hash, "
                "source_id, external_id, title, company, location, source_url, "
                "application_url, reason_code, first_seen_at, last_seen_at) "
                "VALUES (:id, :profile_id, 1, 1, :profile_hash, :source_id, :external_id, "
                ":title, :company, :location, :source_url, :application_url, "
                ":reason_code, :first_seen_at, :last_seen_at)"
            ),
            {
                "id": "review-row",
                "profile_id": profile.id,
                "profile_hash": "a" * 64,
                "source_id": source.id,
                "external_id": "external-1",
                "title": "Senior Frontend Engineer",
                "company": "Acme",
                "location": "Remote",
                "source_url": "https://boards.greenhouse.io/acme/jobs/1",
                "application_url": "https://boards.greenhouse.io/acme/jobs/1",
                "reason_code": "region_unknown",
                "first_seen_at": datetime.now(UTC).isoformat(),
                "last_seen_at": datetime.now(UTC).isoformat(),
            },
        )
        session.commit()
    engine.dispose()

    migration_path = ROOT / "alembic" / "versions" / "aa05_location_unconfirmed.py"
    spec = importlib.util.spec_from_file_location("aa05_location_unconfirmed", migration_path)
    assert spec is not None and spec.loader is not None
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    engine = create_engine(f"sqlite:///{database}")
    with engine.connect() as connection:
        driver = connection.connection.driver_connection
        before = driver.total_changes
        with (
            Operations.context(MigrationContext.configure(connection)),
            pytest.raises(RuntimeError, match=r"^location_unconfirmed_not_empty$"),
        ):
            migration.downgrade()
        assert driver.total_changes == before
        assert (
            connection.execute(
                text("select count(*) from location_unconfirmed where id='review-row'")
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(text("select version_num from alembic_version")).scalar_one() == AA05
        )
    engine.dispose()
