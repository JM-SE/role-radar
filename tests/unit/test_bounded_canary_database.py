from __future__ import annotations

import hashlib
import sqlite3
import sys
from pathlib import Path

import pytest

from scripts import bounded_canary_database as adapter

REVISION = "aa04_bounded_canary_execution"


def _database() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL);
        INSERT INTO alembic_version VALUES ('aa04_bounded_canary_execution');
        CREATE TABLE job_search_runs (
            id TEXT PRIMARY KEY, status TEXT NOT NULL, profile_id TEXT,
            started_at TEXT, completed_at TEXT, claimed_by TEXT,
            lease_expires_at TEXT, heartbeat_at TEXT, recovery_count INTEGER,
            canary_budget_json TEXT, canary_checkpoint_json TEXT
        );
        CREATE TABLE notification_batches (id TEXT, run_id TEXT, status TEXT NOT NULL);
        CREATE TABLE notification_items (id TEXT, batch_id TEXT, run_id TEXT, status TEXT NOT NULL);
        """
    )
    return connection


LOCATION_UNCONFIRMED_DDL = """
CREATE TABLE location_unconfirmed (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    profile_id VARCHAR(36) NOT NULL,
    profile_version INTEGER NOT NULL CONSTRAINT ck_location_unconfirmed_profile_version
        CHECK (profile_version > 0),
    profile_schema_version INTEGER NOT NULL
        CONSTRAINT ck_location_unconfirmed_profile_schema_version
        CHECK (profile_schema_version > 0),
    profile_hash VARCHAR(64) NOT NULL CONSTRAINT ck_location_unconfirmed_profile_hash_length
        CHECK (length(profile_hash) = 64),
    source_id VARCHAR(36) NOT NULL,
    external_id VARCHAR(255) NOT NULL CONSTRAINT ck_location_unconfirmed_external_id
        CHECK (length(trim(external_id)) > 0),
    title VARCHAR(255) NOT NULL CONSTRAINT ck_location_unconfirmed_title
        CHECK (length(trim(title)) > 0),
    company VARCHAR(255) NOT NULL CONSTRAINT ck_location_unconfirmed_company
        CHECK (length(trim(company)) > 0),
    location VARCHAR(255),
    source_url VARCHAR(2048),
    application_url VARCHAR(2048) NOT NULL
        CONSTRAINT ck_location_unconfirmed_application_url
        CHECK (length(trim(application_url)) > 0),
    reason_code VARCHAR(32) NOT NULL CONSTRAINT ck_location_unconfirmed_reason_code
        CHECK (reason_code = 'region_unknown'),
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    CONSTRAINT uq_location_unconfirmed_profile_source_external
        UNIQUE (profile_id, source_id, external_id),
    CONSTRAINT fk_location_unconfirmed_profile
        FOREIGN KEY (profile_id) REFERENCES candidate_profiles (id) ON DELETE CASCADE,
    CONSTRAINT fk_location_unconfirmed_source
        FOREIGN KEY (source_id) REFERENCES sources (id) ON DELETE RESTRICT
)
"""
LOCATION_UNCONFIRMED_INDEX = (
    "CREATE INDEX ix_location_unconfirmed_profile_binding_last_seen "
    "ON location_unconfirmed "
    "(profile_id, profile_version, profile_schema_version, profile_hash, last_seen_at)"
)


def _database_aa05(
    table_ddl: str = LOCATION_UNCONFIRMED_DDL, *, include_index: bool = True
) -> sqlite3.Connection:
    connection = _database()
    connection.execute(
        "UPDATE alembic_version SET version_num='aa05_location_unconfirmed'"
    )
    connection.executescript(
        """
        CREATE TABLE candidate_profiles (id VARCHAR(36) PRIMARY KEY);
        CREATE TABLE sources (id VARCHAR(36) PRIMARY KEY);
        """
    )
    connection.executescript(table_ddl)
    if include_index:
        connection.execute(LOCATION_UNCONFIRMED_INDEX)
    return connection


def _invoke(
    monkeypatch, connection: sqlite3.Connection, database_url: str = "sqlite:///./data/test.db"
) -> tuple[int, str, str]:
    class OpenConnection:
        def __getattr__(self, name):
            return getattr(connection, name)

        def close(self) -> None:
            pass

    def connect(_url: str) -> sqlite3.Connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return OpenConnection()

    monkeypatch.setattr(adapter, "_connect_database", connect)
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    code = adapter.main(["--database-url", database_url])
    return code, "".join(stdout), "".join(stderr)


class _Capture:
    def __init__(self, output: list[str]):
        self.output = output

    def write(self, value: str) -> int:
        self.output.append(value)
        return len(value)

    def flush(self) -> None:
        pass


def test_public_cli_pass_is_fixed_and_does_not_write(monkeypatch) -> None:
    connection = _database()
    before = connection.total_changes
    result = _invoke(monkeypatch, connection)
    assert result == (
        0,
        "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n",
        "",
    )
    assert connection.total_changes == before
    assert connection.execute("PRAGMA query_only").fetchone() == (1,)
    connection.close()


@pytest.mark.parametrize(
    "argv",
    [
        ["--database-url", "sqlite:///missing-first.db", "--database-url", "sqlite:///valid.db"],
        ["--database-url", "sqlite:///valid.db", "--database-url", "sqlite:///missing-last.db"],
        ["--database-url=sqlite:///valid.db", "--database-url", "sqlite:///valid.db"],
        ["--database-u", "sqlite:///missing-first.db", "--database-url", "sqlite:///valid.db"],
    ],
    ids=("missing-then-valid", "valid-then-missing", "duplicate-equals-form", "no-abbrev-bypass"),
)
def test_public_cli_rejects_duplicate_database_urls_before_opening(argv, monkeypatch) -> None:
    connection = _database()
    before = connection.total_changes
    opened = []

    class OpenConnection:
        def __getattr__(self, name):
            return getattr(connection, name)

        def close(self) -> None:
            pass

    def connect(database_url: str):
        opened.append(database_url)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return OpenConnection()

    stdout, stderr = [], []
    monkeypatch.setattr(adapter, "_connect_database", connect)
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(argv)
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (arguments_invalid)\n"
    assert opened == []
    assert connection.total_changes == before
    assert connection.execute("SELECT count(*) FROM job_search_runs").fetchone() == (0,)
    connection.close()


def test_public_cli_help_remains_available(monkeypatch) -> None:
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    with pytest.raises(SystemExit) as exit_info:
        adapter.main(["--help"])
    assert exit_info.value.code == 0
    assert "--database-url" in "".join(stdout)
    assert "SQLite file URL" in "".join(stdout)
    assert "".join(stderr) == ""


def test_public_cli_rejects_wrong_revision_without_disclosing_rows(monkeypatch) -> None:
    connection = _database()
    connection.execute("UPDATE alembic_version SET version_num='other'")
    before = connection.total_changes
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (schema_revision_invalid)\n")
    assert connection.total_changes == before
    assert "other" not in result[1] + result[2]
    connection.close()


def test_history_snapshot_is_metadata_only_and_keeps_deferred_unclaimed(monkeypatch) -> None:
    connection = _database()
    connection.execute(
        "INSERT INTO job_search_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("private-run-id", "deferred", None, "start", "done", None, None, "beat", 2, None, None),
    )
    before = connection.total_changes
    snapshot = adapter.snapshot_history(connection)
    assert snapshot["runs"] == (
        {
            "id": "private-run-id",
            "status": "deferred",
            "profile_id": None,
            "started_at": "start",
            "completed_at": "done",
            "claimed_by": None,
            "lease_expires_at": None,
            "heartbeat_at": "beat",
            "recovery_count": 2,
        },
    )
    assert "private-run-id" not in adapter._public_snapshot_summary(snapshot)
    assert connection.total_changes == before
    connection.close()


def test_public_cli_rejects_pending_run_and_unknown_outbox_state(monkeypatch) -> None:
    connection = _database()
    connection.execute(
        "INSERT INTO job_search_runs VALUES "
        "('run-private', 'pending', NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL)"
    )
    connection.execute(
        "INSERT INTO notification_batches VALUES ('batch-private', 'run-private', 'mystery')"
    )
    before = connection.total_changes
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (run_history_unresolved)\n")
    assert connection.total_changes == before
    assert "private" not in result[1] + result[2]
    connection.close()


def test_public_cli_rejects_missing_required_table(monkeypatch) -> None:
    connection = _database()
    connection.execute("DROP TABLE notification_items")
    before = connection.total_changes
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (schema_invalid)\n")
    assert connection.total_changes == before
    connection.close()


def test_in_progress_run_is_rejected(monkeypatch) -> None:
    connection = _database()
    connection.execute(
        "INSERT INTO job_search_runs VALUES "
        "('run-private', 'collecting', NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL)"
    )
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (run_history_unresolved)\n")
    connection.close()


def test_missing_aa04_budget_column_fails_closed(monkeypatch) -> None:
    connection = _database()
    connection.execute("ALTER TABLE job_search_runs DROP COLUMN canary_budget_json")
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (schema_invalid)\n")
    connection.close()


def test_aa05_review_schema_passes_read_only_gate(monkeypatch) -> None:
    connection = _database_aa05()
    before = connection.total_changes
    result = _invoke(monkeypatch, connection)
    assert result == (
        0,
        "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n",
        "",
    )
    assert connection.total_changes == before
    assert connection.execute("PRAGMA query_only").fetchone() == (1,)
    connection.close()


_REVIEW_REASON_CHECK = (
    "    reason_code VARCHAR(32) NOT NULL "
    "CONSTRAINT ck_location_unconfirmed_reason_code\n"
    "        CHECK (reason_code = 'region_unknown'),\n"
)
_REVIEW_REASON_CHECK_ALLOW_ELIGIBLE = (
    "    reason_code VARCHAR(32) NOT NULL "
    "CONSTRAINT ck_location_unconfirmed_reason_code\n"
    "        CHECK (reason_code IN ('region_unknown', 'eligible')),\n"
)
_PROFILE_FOREIGN_KEY = (
    "    CONSTRAINT fk_location_unconfirmed_profile\n"
    "        FOREIGN KEY (profile_id) REFERENCES candidate_profiles (id) ON DELETE CASCADE,\n"
)


def test_aa05_gate_rejects_partial_unique_identity_index(monkeypatch) -> None:
    table_ddl = LOCATION_UNCONFIRMED_DDL.replace(
        "    CONSTRAINT uq_location_unconfirmed_profile_source_external\n"
        "        UNIQUE (profile_id, source_id, external_id),\n",
        "",
    )
    connection = _database_aa05(table_ddl)
    connection.execute(
        "CREATE UNIQUE INDEX weak_unique ON location_unconfirmed "
        "(profile_id, source_id, external_id) WHERE reason_code='eligible'"
    )
    before = connection.total_changes
    try:
        assert _invoke(monkeypatch, connection) == (
            1,
            "",
            "DATABASE_HISTORY_GATE: FAIL (schema_invalid)\n",
        )
        assert connection.total_changes == before
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
    finally:
        connection.close()


def test_aa05_gate_does_not_accept_check_text_inside_comment(monkeypatch) -> None:
    table_ddl = LOCATION_UNCONFIRMED_DDL.replace(
        "CHECK (reason_code = 'region_unknown')",
        "/* CHECK (reason_code = 'region_unknown') */ "
        "CHECK (reason_code IN ('region_unknown', 'eligible'))",
    )
    connection = _database_aa05(table_ddl)
    before = connection.total_changes
    try:
        assert _invoke(monkeypatch, connection) == (
            1,
            "",
            "DATABASE_HISTORY_GATE: FAIL (schema_invalid)\n",
        )
        assert connection.total_changes == before
        assert connection.execute("PRAGMA query_only").fetchone() == (1,)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("table_ddl", "include_index"),
    [
        (
            LOCATION_UNCONFIRMED_DDL.replace(
                _REVIEW_REASON_CHECK,
                "    reason_code VARCHAR(32) NOT NULL,\n",
            ),
            True,
        ),
        (
            LOCATION_UNCONFIRMED_DDL.replace(
                _REVIEW_REASON_CHECK,
                _REVIEW_REASON_CHECK_ALLOW_ELIGIBLE,
            ),
            True,
        ),
        (LOCATION_UNCONFIRMED_DDL.replace(_PROFILE_FOREIGN_KEY, ""), True),
        (
            LOCATION_UNCONFIRMED_DDL.replace("title VARCHAR(255) NOT NULL", "title VARCHAR(255)"),
            True,
        ),
        (
            LOCATION_UNCONFIRMED_DDL.replace(
                "    CONSTRAINT uq_location_unconfirmed_profile_source_external\n"
                "        UNIQUE (profile_id, source_id, external_id),\n",
                "",
            ),
            True,
        ),
        (LOCATION_UNCONFIRMED_DDL, False),
        (
            LOCATION_UNCONFIRMED_DDL.replace(
                "profile_version INTEGER NOT NULL", "profile_version TEXT NOT NULL"
            ),
            True,
        ),
    ],
    ids=(
        "missing-reason-check",
        "eligible-reason-allowed",
        "missing-foreign-keys",
        "nullable-title",
        "missing-unique",
        "missing-index",
        "wrong-column-type",
    ),
)
def test_aa05_malformed_review_schema_fails_closed_without_writes(
    table_ddl: str, include_index: bool, monkeypatch
) -> None:
    connection = _database_aa05(table_ddl, include_index=include_index)
    before = connection.total_changes
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (schema_invalid)\n")
    assert connection.total_changes == before
    assert connection.execute("PRAGMA query_only").fetchone() == (1,)
    assert connection.execute("SELECT count(*) FROM location_unconfirmed").fetchone() == (0,)
    connection.close()


def test_claimed_deferred_run_and_lease_are_rejected(monkeypatch) -> None:
    for claim, lease in (("worker-private", None), (None, "lease-private")):
        connection = _database()
        connection.execute(
            "INSERT INTO job_search_runs VALUES "
            "('id-private', 'deferred', NULL, NULL, NULL, ?, ?, NULL, 1, NULL, NULL)",
            (claim, lease),
        )
        result = _invoke(monkeypatch, connection)
        assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (run_history_unresolved)\n")
        assert "private" not in result[1] + result[2]
        connection.close()


def test_terminal_outbox_rows_pass_and_unknown_item_fails_closed(monkeypatch) -> None:
    connection = _database()
    connection.execute(
        "INSERT INTO notification_batches VALUES ('batch-id', 'run-id', 'sent')"
    )
    connection.execute(
        "INSERT INTO notification_items VALUES ('item-id', 'batch-id', 'run-id', 'failed')"
    )
    assert _invoke(monkeypatch, connection) == (
        0,
        "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n",
        "",
    )
    connection.close()

    connection = _database()
    connection.execute(
        "INSERT INTO notification_batches VALUES ('batch-private', 'run-id', 'unknown')"
    )
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (outbox_unresolved)\n")
    connection.close()

    connection = _database()
    connection.execute(
        "INSERT INTO notification_items VALUES ('item-private', 'batch-id', 'run-id', 'unknown')"
    )
    result = _invoke(monkeypatch, connection)
    assert result == (1, "", "DATABASE_HISTORY_GATE: FAIL (outbox_unresolved)\n")
    assert "private" not in result[1] + result[2]
    connection.close()


def _file_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, isolation_level=None)
    connection.executescript(
        """
        CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL);
        INSERT INTO alembic_version VALUES ('aa04_bounded_canary_execution');
        CREATE TABLE job_search_runs (
            id TEXT PRIMARY KEY, status TEXT NOT NULL, profile_id TEXT,
            started_at TEXT, completed_at TEXT, claimed_by TEXT,
            lease_expires_at TEXT, heartbeat_at TEXT, recovery_count INTEGER,
            canary_budget_json TEXT, canary_checkpoint_json TEXT
        );
        CREATE TABLE notification_batches (
            id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES job_search_runs(id),
            status TEXT NOT NULL
        );
        CREATE TABLE notification_items (
            id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES notification_batches(id),
            run_id TEXT NOT NULL REFERENCES job_search_runs(id), status TEXT NOT NULL
        );
        """
    )
    return connection


def _file_hash(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _sidecar_state(path: Path) -> dict[str, tuple[str | None, str | None]]:
    state = {}
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        mode = oct(candidate.stat().st_mode & 0o777) if candidate.exists() else None
        state[candidate.name] = (_file_hash(candidate), mode)
    return state


def test_absolute_sqlite_url_passes_public_cli(monkeypatch) -> None:
    connection = _database()
    result = _invoke(monkeypatch, connection, "sqlite:////tmp/canary.db")
    assert result == (
        0,
        "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n",
        "",
    )
    connection.close()


def test_failed_connection_setup_closes_open_handle(monkeypatch, tmp_path: Path) -> None:
    class BrokenConnection:
        closed = False

        def execute(self, _query: str):
            raise sqlite3.OperationalError("private sqlite details")

        def close(self) -> None:
            self.closed = True

    broken = BrokenConnection()
    monkeypatch.setattr(adapter, "_database_path", lambda _url: tmp_path / "fixture.db")
    monkeypatch.setattr(adapter, "_file_identity", lambda _path: (1, 2, 3, 4, 5, 6, 0))
    monkeypatch.setattr(adapter.sqlite3, "connect", lambda *args, **kwargs: broken)
    with pytest.raises(adapter.GateError, match="database_unavailable"):
        adapter._connect_database("sqlite:///fixture.db")
    assert broken.closed is True


def test_public_cli_bad_arguments_use_fixed_output(monkeypatch) -> None:
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", "sqlite:///private.db", "--unknown-secret-arg"])
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (arguments_invalid)\n"
    assert "private" not in "".join(stderr)
    assert "unknown-secret-arg" not in "".join(stderr)


def test_real_readonly_connection_and_public_cli_preserve_database(
    tmp_path: Path, monkeypatch
) -> None:
    path = tmp_path / "real-readonly.db"
    writer = _file_database(path)
    writer.execute(
        "INSERT INTO job_search_runs VALUES "
        "('run-a', 'completed', NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL)"
    )
    writer.execute(
        "INSERT INTO notification_batches VALUES ('batch-a', 'run-a', 'sent')"
    )
    writer.execute(
        "INSERT INTO notification_items VALUES ('item-a', 'batch-a', 'run-a', 'failed')"
    )
    writer.execute("CREATE TABLE private_payload_fixture(body TEXT)")
    writer.execute("INSERT INTO private_payload_fixture VALUES ('private-body-marker')")
    writer.close()
    before = _sidecar_state(path)

    connection = adapter._connect_database(f"sqlite:///{path}")
    assert connection.execute("PRAGMA query_only").fetchone() == (1,)
    connection.execute("PRAGMA query_only=OFF")
    with pytest.raises(sqlite3.OperationalError):
        connection.execute(
            "INSERT INTO job_search_runs(id, status) VALUES ('blocked', 'completed')"
        )
    connection.close()

    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", f"sqlite:///{path}"])
    after = _sidecar_state(path)
    print(f"READONLY_SIDECARS before={before} after={after}", file=sys.__stdout__)
    assert result == 0
    assert "".join(stdout) == "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n"
    assert "".join(stderr) == ""
    assert "private-body-marker" not in "".join(stdout) + "".join(stderr)
    assert before == after
    check = sqlite3.connect(path)
    assert check.execute("SELECT id FROM job_search_runs").fetchall() == [("run-a",)]
    check.close()


def test_missing_file_is_not_created_and_symlink_fails_closed(tmp_path: Path, monkeypatch) -> None:
    missing = tmp_path / "missing.db"
    before = set(tmp_path.iterdir())
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", f"sqlite:///{missing}"])
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_unavailable)\n"
    assert set(tmp_path.iterdir()) == before
    assert not missing.exists()
    stdout.clear()
    stderr.clear()

    target = tmp_path / "target.db"
    writer = _file_database(target)
    writer.close()
    alias = tmp_path / "alias.db"
    alias.symlink_to(target)
    before_target = _sidecar_state(target)
    result = adapter.main(["--database-url", f"sqlite:///{alias}"])
    assert result == 1
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_target_invalid)\n"
    assert before_target == _sidecar_state(target)


def test_real_wal_reader_sees_uncheckpointed_history_and_records_sidecars(
    tmp_path: Path,
) -> None:
    path = tmp_path / "wal.db"
    writer = _file_database(path)
    assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute(
        "INSERT INTO job_search_runs VALUES "
        "('wal-run', 'deferred', NULL, NULL, NULL, NULL, NULL, NULL, 1, NULL, NULL)"
    )
    before = _sidecar_state(path)
    assert before[f"{path.name}-wal"][0] is not None

    connection = adapter._connect_database(f"sqlite:///{path}")
    snapshot = adapter.snapshot_history(connection)
    assert snapshot["runs"][0]["id"] == "wal-run"
    adapter._validate_history(snapshot)
    connection.close()
    after = _sidecar_state(path)
    print(f"WAL_SIDECARS before={before} after={after}")
    assert before[path.name][0] == after[path.name][0]
    assert before[f"{path.name}-wal"][0] == after[f"{path.name}-wal"][0]
    assert writer.execute("SELECT id FROM job_search_runs").fetchall() == [("wal-run",)]
    writer.close()


def test_wal_mode_without_existing_sidecars_fails_before_open(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "wal-sidecars-missing.db"
    writer = _file_database(path)
    assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    writer.close()
    before = _sidecar_state(path)
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", f"sqlite:///{path}"])
    after = _sidecar_state(path)
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_wal_resources_unavailable)\n"
    assert before == after


def test_relative_sqlite_url_uses_current_working_directory(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "relative.db"
    writer = _file_database(path)
    writer.execute(
        "INSERT INTO job_search_runs VALUES "
        "('run-a', 'completed', NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL)"
    )
    writer.close()
    monkeypatch.chdir(tmp_path)
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", "sqlite:///relative.db"])
    assert result == 0
    assert "".join(stdout) == "DATABASE_HISTORY_GATE: PASS (gate only; not overall readiness)\n"
    assert "".join(stderr) == ""


def test_real_foreign_key_corruption_fails_closed(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "foreign-key.db"
    writer = _file_database(path)
    writer.execute(
        "INSERT INTO notification_batches(id, run_id, status) VALUES ('orphan', 'missing', 'sent')"
    )
    writer.close()
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", f"sqlite:///{path}"])
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_foreign_key_invalid)\n"


def test_sqlite_error_output_is_fixed_and_private(monkeypatch) -> None:
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))

    def fail(_database_url: str):
        raise sqlite3.OperationalError("private SQL path and payload")

    monkeypatch.setattr(adapter, "_connect_database", fail)
    result = adapter.main(["--database-url", "sqlite:///synthetic.db"])
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_inspection_unavailable)\n"
    assert "private" not in "".join(stderr)
    assert "payload" not in "".join(stderr)


def test_credential_url_fails_without_opening_database(monkeypatch) -> None:
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", "sqlite://private:secret@host/db"])
    assert result == 1
    assert "".join(stdout) == ""
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_target_invalid)\n"
    assert "private" not in "".join(stderr)
    assert "secret" not in "".join(stderr)


def test_invalid_url_fails_without_opening_database(monkeypatch) -> None:
    called = False

    def connect(_url: str):
        nonlocal called
        called = True
        raise AssertionError("unexpected database open")

    monkeypatch.setattr(adapter, "_connect_database", connect)
    stdout, stderr = [], []
    monkeypatch.setattr(adapter.sys, "stdout", _Capture(stdout))
    monkeypatch.setattr(adapter.sys, "stderr", _Capture(stderr))
    result = adapter.main(["--database-url", "sqlite:///test.db?mode=rw"])
    assert result == 1
    assert "".join(stderr) == "DATABASE_HISTORY_GATE: FAIL (database_target_invalid)\n"
    assert "".join(stdout) == ""
    assert called is False
