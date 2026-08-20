"""Offline SQLite projection for F10.1C.

The repository intentionally uses sqlite3 instead of the application's ORM:
the allowlist is visible in this file and the returned values are detached
plain projections.  It never opens a write-capable source connection.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from role_radar.evaluation.cohort_freeze.contracts import (
    BoundaryResolution,
    CandidateEvidence,
    IdentityEvidence,
    RepositorySnapshot,
)
from role_radar.evaluation.cohort_freeze.policy import (
    BOUNDARY_RUN_ID,
    canonical_time,
)
from role_radar.evaluation.snapshot_store import sha256_bytes

ALLOWED_TABLES = frozenset(
    {
        "continuous_acquisition_runs",
        "continuous_acquisition_source_operations",
        "continuous_acquisition_run_jobs",
        "jobs",
        "job_identity_keys",
        "candidate_profiles",
        "alembic_version",
    }
)


def _read_only_authorizer(
    action: int, arg1: str | None, _arg2: str | None, _database: str | None, _source: str | None
) -> int:
    denied = {
        sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_REINDEX,
    }
    if action in denied:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and arg1 != "query_only":
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class RepositoryError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _database_path(database: str | Path) -> Path:
    value = str(database)
    if value.startswith("sqlite:///"):
        value = value[10:]
    elif "://" in value:
        raise RepositoryError("database_not_local_sqlite")
    path = Path(value)
    if not path.is_absolute():
        path = path.absolute()
    if path.is_symlink() or not path.is_file():
        raise RepositoryError("database_not_file")
    return path


def _parse_json(value: Any, *, code: str) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str):
        raise RepositoryError(code)
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RepositoryError(code) from exc


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    for key in ("snapshot_json", "source_snapshot_json", "profile_json"):
        if key in result:
            result[key] = _parse_json(result[key], code=f"{key}_invalid")
    return result


class SQLiteSnapshotRepository:
    """Read and freeze one consistent file-backed SQLite snapshot."""

    def __init__(self, database: str | Path, *, boundary_run_id: str = BOUNDARY_RUN_ID) -> None:
        self.database = _database_path(database)
        self.boundary_run_id = boundary_run_id

    @contextmanager
    def _snapshot_connection(self) -> Iterator[sqlite3.Connection]:
        source_uri = f"file:{self.database}?mode=ro"
        source = sqlite3.connect(source_uri, uri=True)
        source.row_factory = sqlite3.Row
        memory = sqlite3.connect(":memory:")
        memory.row_factory = sqlite3.Row
        try:
            source.execute("PRAGMA query_only=ON")
            if source.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise RepositoryError("query_only_not_enabled")
            source.set_authorizer(_read_only_authorizer)
            source.backup(memory)
            memory.execute("PRAGMA query_only=ON")
            if memory.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise RepositoryError("query_only_not_enabled")
            memory.set_authorizer(_read_only_authorizer)
            yield memory
        finally:
            memory.close()
            source.close()

    @staticmethod
    def _tables(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        return {str(row[0]) for row in rows}

    def load(self) -> RepositorySnapshot:
        with self._snapshot_connection() as connection:
            tables = self._tables(connection)
            forbidden = tables - ALLOWED_TABLES
            # Downstream tables must not even be inspected.  A synthetic DB may
            # contain unrelated SQLite metadata, but product tables are blocked.
            if forbidden & {
                "job_source_references",
                "job_extractions",
                "job_scores",
                "deep_evaluation_queue",
                "job_deep_evaluations",
                "labels",
            }:
                raise RepositoryError("downstream_table_access_blocked")
            required = {
                "continuous_acquisition_runs",
                "continuous_acquisition_source_operations",
                "continuous_acquisition_run_jobs",
                "jobs",
                "job_identity_keys",
                "candidate_profiles",
                "alembic_version",
            }
            if not required <= tables:
                raise RepositoryError("required_table_missing")
            runs = tuple(
                _row_dict(row)
                for row in connection.execute(
                    "SELECT id,slot_key,state,snapshot_hash,snapshot_json,policy_version,"
                    "started_at,"
                    "finished_at,created_count,observed_count FROM continuous_acquisition_runs"
                )
            )
            operations = tuple(
                _row_dict(row)
                for row in connection.execute(
                    "SELECT id,run_id,source_id,source_snapshot_json,intent_state,result_state,"
                    "observed_count,created_count,started_at,finished_at FROM "
                    "continuous_acquisition_source_operations"
                )
            )
            links = tuple(
                _row_dict(row)
                for row in connection.execute(
                    "SELECT id,run_id,operation_id,job_id,disposition,provider_recency_at,"
                    "recency_semantic,freshness_policy_version,identity_policy_version,"
                    "provenance_hash,created_at FROM continuous_acquisition_run_jobs"
                )
            )
            jobs = tuple(
                _row_dict(row)
                for row in connection.execute(
                    "SELECT id,title,company,location,description,application_url FROM jobs"
                )
            )
            identities = tuple(
                _row_dict(row)
                for row in connection.execute(
                    "SELECT id,job_id,identity_kind,identity_version,identity_value,value_digest "
                    "FROM job_identity_keys"
                )
            )
            profiles = tuple(
                _row_dict(row)
                for row in connection.execute(
                    "SELECT id,name,version,schema_version,profile_json,is_active "
                    "FROM candidate_profiles "
                    "WHERE is_active = 1"
                )
            )
            alembic = tuple(
                _row_dict(row)
                for row in connection.execute("SELECT version_num FROM alembic_version")
            )
            fingerprint = sha256_bytes(connection.serialize())

        boundary_rows = [row for row in runs if str(row["id"]) == self.boundary_run_id]
        if len(boundary_rows) != 1:
            raise RepositoryError("boundary_missing_or_duplicate")
        boundary_row = boundary_rows[0]
        try:
            boundary_started = canonical_time(boundary_row["started_at"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise RepositoryError("boundary_timestamp_invalid") from exc
        boundary = BoundaryResolution(
            run_id=self.boundary_run_id,
            started_at_utc=boundary_started,
            run_state=str(boundary_row["state"]),
        )
        selected_runs = tuple(
            row for row in runs if self._run_key(row) >= (boundary_started, self.boundary_run_id)
        )
        snapshot = RepositorySnapshot(
            boundary=boundary,
            fingerprint=fingerprint,
            deployment={},
            runs=selected_runs,
            operations=tuple(
                row for row in operations if row["run_id"] in {r["id"] for r in selected_runs}
            ),
            links=tuple(row for row in links if row["run_id"] in {r["id"] for r in selected_runs}),
            jobs=jobs,
            identities=identities,
            profile=self._active_profile(profiles),
            alembic_version=self._alembic(alembic),
        )
        return replace(snapshot, candidates=self._candidates(snapshot))

    snapshot = load
    read = load

    @contextmanager
    def read_only_connection(self) -> Iterator[sqlite3.Connection]:
        with self._snapshot_connection() as connection:
            yield connection

    @staticmethod
    def _run_key(row: dict[str, Any]) -> tuple[str, str]:
        try:
            started = canonical_time(row["started_at"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise RepositoryError("run_timestamp_invalid") from exc
        return started, str(row["id"])

    @staticmethod
    def _active_profile(rows: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        if len(rows) != 1:
            raise RepositoryError("active_profile_missing_or_ambiguous")
        return rows[0]

    @staticmethod
    def _alembic(rows: tuple[dict[str, Any], ...]) -> str:
        if len(rows) != 1:
            raise RepositoryError("alembic_head_missing_or_ambiguous")
        return str(rows[0]["version_num"])

    @staticmethod
    def _candidates(snapshot: RepositorySnapshot) -> tuple[CandidateEvidence, ...]:
        runs = {row["id"]: row for row in snapshot.runs}
        operations = {row["id"]: row for row in snapshot.operations}
        jobs = {row["id"]: row for row in snapshot.jobs}
        identities: dict[str, list[IdentityEvidence]] = {}
        identities_by_key: dict[tuple[str, str, str], list[IdentityEvidence]] = {}
        for row in snapshot.identities:
            item = IdentityEvidence(
                kind=str(row["identity_kind"]),
                version=str(row["identity_version"]),
                value=str(row["identity_value"]),
                value_digest=str(row["value_digest"]),
                owner_job_id=str(row["job_id"]),
            )
            identities.setdefault(str(row["job_id"]), []).append(item)
            identities_by_key.setdefault(
                (item.version, item.kind, item.value), []
            ).append(item)
        links_by_operation: dict[str, int] = {}
        for link in snapshot.links:
            links_by_operation[str(link["operation_id"])] = (
                links_by_operation.get(str(link["operation_id"]), 0) + 1
            )
        result: list[CandidateEvidence] = []
        for row in snapshot.links:
            run = runs.get(row["run_id"])
            operation = operations.get(row["operation_id"])
            own_identities = identities.get(str(row["job_id"]), ())
            shared_identities = tuple(
                shared
                for identity in own_identities
                for shared in identities_by_key.get(
                    (identity.version, identity.kind, identity.value), ()
                )
                if shared.owner_job_id != str(row["job_id"])
            )
            result.append(
                CandidateEvidence(
                    run_id=str(row["run_id"]),
                    run_started_at=run["started_at"] if run else "",
                    run_state=str(run["state"]) if run else "",
                    run_policy_version=str(run["policy_version"]) if run else "",
                    run_snapshot_json=run.get("snapshot_json") if run else None,
                    run_snapshot_hash=str(run.get("snapshot_hash", "")) if run else "",
                    link_id=str(row["id"]),
                    operation_id=str(row["operation_id"]),
                    job_id=str(row["job_id"]),
                    disposition=str(row["disposition"]),
                    operation_run_id=str(operation["run_id"]) if operation else None,
                    operation_source_id=str(operation["source_id"]) if operation else None,
                    operation_result_state=str(operation["result_state"])
                    if operation and operation["result_state"] is not None
                    else None,
                    operation_finished_at=operation.get("finished_at") if operation else None,
                    operation_created_count=int(operation.get("created_count", 0))
                    if operation
                    else 0,
                    operation_observed_count=int(operation.get("observed_count", 0))
                    if operation
                    else 0,
                    run_created_count=int(run.get("created_count", 0)) if run else 0,
                    run_observed_count=int(run.get("observed_count", 0)) if run else 0,
                    source_snapshot_json=operation.get("source_snapshot_json")
                    if operation
                    else None,
                    accepted_observation_at=row.get("created_at"),
                    provider_recency_at=row.get("provider_recency_at"),
                    recency_semantic=row.get("recency_semantic"),
                    freshness_policy_version=row.get("freshness_policy_version"),
                    identity_policy_version=row.get("identity_policy_version"),
                    provenance_hash=row.get("provenance_hash"),
                    title=jobs.get(row["job_id"], {}).get("title")
                    if row["job_id"] in jobs
                    else None,
                    company=jobs.get(row["job_id"], {}).get("company")
                    if row["job_id"] in jobs
                    else None,
                    location=jobs.get(row["job_id"], {}).get("location")
                    if row["job_id"] in jobs
                    else None,
                    description=jobs.get(row["job_id"], {}).get("description")
                    if row["job_id"] in jobs
                    else None,
                    application_url=jobs.get(row["job_id"], {}).get("application_url")
                    if row["job_id"] in jobs
                    else None,
                    identity_keys=tuple(own_identities) + shared_identities,
                    source_type=(operation.get("source_snapshot_json") or {}).get("type")
                    if operation
                    else None,
                    job_exists=row["job_id"] in jobs,
                )
            )
        return tuple(result)


Repository = SQLiteSnapshotRepository

SQLiteRepository = SQLiteSnapshotRepository
CohortRepository = SQLiteSnapshotRepository

__all__ = [
    "ALLOWED_TABLES",
    "CohortRepository",
    "Repository",
    "RepositoryError",
    "SQLiteRepository",
    "SQLiteSnapshotRepository",
]
