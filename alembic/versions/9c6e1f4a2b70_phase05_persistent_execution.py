"""phase05_persistent_execution — durable runs, leases and checkpoints.

This revision is intentionally chained to the real F4 head.  Historical rows
are kept conservative: no profile is inferred and no historical error text is
converted into a made-up code.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa

from alembic import op

revision: str = "9c6e1f4a2b70"
down_revision: str | None = "8a4d2f6c9b10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "job_extractions",
        sa.Column("active_corrective_attempt", sa.Integer(), nullable=True),
    )
    op.add_column(
        "job_extractions",
        sa.Column("request_fingerprint", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "job_extractions",
        sa.Column("processing_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "UPDATE job_extractions SET active_corrective_attempt = 0 "
        "WHERE active_corrective_attempt IS NULL"
    )
    with op.batch_alter_table("job_extractions") as batch:
        batch.alter_column(
            "active_corrective_attempt",
            existing_type=sa.Integer(),
            nullable=False,
            server_default="0",
        )
        batch.create_check_constraint(
            "ck_job_extractions_active_corrective_attempt",
            "active_corrective_attempt IN (0, 1)",
        )
    op.create_index(
        "ix_job_extractions_request_fingerprint", "job_extractions", ["request_fingerprint"]
    )

    run_columns: list[Any] = [
        sa.Column("profile_id", sa.String(length=36), nullable=True),
        sa.Column("retry_of_run_id", sa.String(length=36), nullable=True),
        sa.Column("trigger_key_hash", sa.String(length=64), nullable=True),
        sa.Column("request_hash", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("source_snapshot_json", sa.JSON(), nullable=True),
        sa.Column("source_results_json", sa.JSON(), nullable=True),
        sa.Column("claimed_by", sa.String(length=255), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovery_count", sa.Integer(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    ]
    for column in run_columns:
        op.add_column("job_search_runs", column)
    op.execute("UPDATE job_search_runs SET request_hash = '' WHERE request_hash IS NULL")
    op.execute("UPDATE job_search_runs SET recovery_count = 0 WHERE recovery_count IS NULL")
    op.execute("UPDATE job_search_runs SET updated_at = created_at WHERE updated_at IS NULL")
    with op.batch_alter_table("job_search_runs") as batch:
        batch.alter_column("request_hash", existing_type=sa.String(length=64), nullable=False)
        batch.alter_column(
            "recovery_count", existing_type=sa.Integer(), nullable=False, server_default="0"
        )
        batch.create_foreign_key(
            "fk_job_search_runs_profile", "candidate_profiles", ["profile_id"], ["id"]
        )
        batch.create_foreign_key(
            "fk_job_search_runs_retry_parent", "job_search_runs", ["retry_of_run_id"], ["id"]
        )

    op.create_index(
        "ix_job_search_runs_pending_created", "job_search_runs", ["status", "created_at"]
    )
    op.create_index(
        "ix_job_search_runs_recovery",
        "job_search_runs",
        ["status", "lease_expires_at", "created_at"],
    )
    op.create_index("ix_job_search_runs_profile", "job_search_runs", ["profile_id"])
    op.create_index("ix_job_search_runs_retry_parent", "job_search_runs", ["retry_of_run_id"])
    op.create_index(
        "ix_job_search_runs_trigger_key_hash", "job_search_runs", ["trigger_key_hash"], unique=True
    )

    run_job_columns: list[Any] = [
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome_json", sa.JSON(), nullable=True),
    ]
    for column in run_job_columns:
        op.add_column("run_jobs", column)
    op.execute(
        "UPDATE run_jobs SET attempt_count = CASE "
        "WHEN status IN ('succeeded', 'failed', 'skipped') THEN 1 ELSE 0 END "
        "WHERE attempt_count IS NULL"
    )
    with op.batch_alter_table("run_jobs") as batch:
        batch.alter_column(
            "attempt_count", existing_type=sa.Integer(), nullable=False, server_default="0"
        )


def downgrade() -> None:
    with op.batch_alter_table("run_jobs") as batch:
        batch.drop_column("outcome_json")
        batch.drop_column("next_attempt_at")
        batch.drop_column("completed_at")
        batch.drop_column("started_at")
        batch.drop_column("attempt_count")
        batch.drop_column("error_code")

    op.drop_index("ix_job_search_runs_trigger_key_hash", table_name="job_search_runs")
    op.drop_index("ix_job_search_runs_retry_parent", table_name="job_search_runs")
    op.drop_index("ix_job_search_runs_profile", table_name="job_search_runs")
    op.drop_index("ix_job_search_runs_recovery", table_name="job_search_runs")
    op.drop_index("ix_job_search_runs_pending_created", table_name="job_search_runs")
    with op.batch_alter_table("job_search_runs") as batch:
        batch.drop_constraint("fk_job_search_runs_retry_parent", type_="foreignkey")
        batch.drop_constraint("fk_job_search_runs_profile", type_="foreignkey")
        batch.drop_column("updated_at")
        batch.drop_column("recovery_count")
        batch.drop_column("heartbeat_at")
        batch.drop_column("lease_expires_at")
        batch.drop_column("claimed_by")
        batch.drop_column("source_results_json")
        batch.drop_column("source_snapshot_json")
        batch.drop_column("error_code")
        batch.drop_column("request_hash")
        batch.drop_column("trigger_key_hash")
        batch.drop_column("retry_of_run_id")
        batch.drop_column("profile_id")

    op.drop_index("ix_job_extractions_request_fingerprint", table_name="job_extractions")
    # SQLite reflects the CHECK constraint created above without its source
    # column, so Alembic's generic batch drop cannot rebuild this table. The
    # application database is SQLite-only; rebuild it explicitly with the F3
    # shape while preserving the original unique constraint and index.
    op.execute("PRAGMA foreign_keys=OFF")
    op.execute(
        """
        CREATE TABLE _alembic_tmp_job_extractions (
            id VARCHAR(36) NOT NULL,
            job_id VARCHAR(36) NOT NULL,
            schema_version VARCHAR(64) NOT NULL,
            prompt_version VARCHAR(64) NOT NULL,
            model_capability VARCHAR(64) NOT NULL,
            model_identifier VARCHAR(255),
            broker_task_id VARCHAR(128),
            input_hash VARCHAR(64) NOT NULL,
            extraction_json JSON,
            validation_status VARCHAR(16) NOT NULL,
            attempt_count INTEGER DEFAULT '0' NOT NULL,
            error_class VARCHAR(64),
            error_code VARCHAR(128),
            finish_reason VARCHAR(32),
            usage_json JSON,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT uq_job_extractions_operation
                UNIQUE (job_id, input_hash, schema_version, prompt_version),
            FOREIGN KEY(job_id) REFERENCES jobs (id)
        )
        """
    )
    op.execute(
        """
        INSERT INTO _alembic_tmp_job_extractions (
            id, job_id, schema_version, prompt_version, model_capability,
            model_identifier, broker_task_id, input_hash, extraction_json,
            validation_status, attempt_count, error_class, error_code,
            finish_reason, usage_json, created_at, updated_at
        )
        SELECT id, job_id, schema_version, prompt_version, model_capability,
            model_identifier, broker_task_id, input_hash, extraction_json,
            validation_status, attempt_count, error_class, error_code,
            finish_reason, usage_json, created_at, updated_at
        FROM job_extractions
        """
    )
    op.drop_table("job_extractions")
    op.rename_table("_alembic_tmp_job_extractions", "job_extractions")
    op.create_index("ix_job_extractions_job_id", "job_extractions", ["job_id"])
    op.execute("PRAGMA foreign_keys=ON")
