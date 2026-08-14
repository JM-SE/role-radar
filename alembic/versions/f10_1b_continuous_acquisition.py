"""Phase 10.1B offline journal, identity and provenance tables.

This revision is intentionally additive.  It never rewrites historical Job
rows and refuses to backfill an ambiguous strong identity collision.
"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f101b_continuous"
down_revision: str | None = "e7a4c9f1b2d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _common_run_columns() -> list[sa.Column[object]]:
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("slot_key", sa.String(128), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F10.1B migration currently supports SQLite only")

    op.create_table(
        "source_discovery_runs",
        *_common_run_columns(),
        sa.Column("config_version", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(128)), sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("fencing_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)), sa.Column("provider", sa.String(32)),
        sa.Column("candidate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reserved_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("registered_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("terminal_code", sa.String(64)),
        sa.UniqueConstraint("slot_key", name="uq_source_discovery_runs_slot_key"),
        sa.CheckConstraint("state IN ('planned','running','completed','partial','failed','indeterminate')", name="ck_source_discovery_runs_state"),
        sa.CheckConstraint("candidate_count >= 0 AND reserved_count >= 0 AND verified_count >= 0 AND registered_count >= 0", name="ck_source_discovery_runs_counts"),
    )
    op.create_index("ix_source_discovery_runs_state", "source_discovery_runs", ["state"])
    op.create_table(
        "source_discovery_operations",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("operation_key", sa.String(255), nullable=False), sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("operation_type", sa.String(32), nullable=False), sa.Column("intent_state", sa.String(20), nullable=False),
        sa.Column("result_state", sa.String(20)), sa.Column("reserved_capacity", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"), sa.Column("candidate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("result_code", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["run_id"], ["source_discovery_runs.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("run_id", "operation_key", name="uq_source_discovery_operations_key"),
        sa.CheckConstraint("intent_state IN ('intent','succeeded','failed','indeterminate')", name="ck_source_discovery_operations_intent"),
        sa.CheckConstraint("result_state IS NULL OR result_state IN ('succeeded','empty','failed','indeterminate')", name="ck_source_discovery_operations_result"),
        sa.CheckConstraint("reserved_capacity >= 0 AND attempts >= 0 AND candidate_count >= 0 AND verified_count >= 0", name="ck_source_discovery_operations_counts"),
    )
    op.create_index("ix_source_discovery_operations_run", "source_discovery_operations", ["run_id"])
    op.create_table(
        "source_discovery_registrations",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("operation_id", sa.String(36), nullable=False), sa.Column("source_id", sa.String(36)),
        sa.Column("source_key", sa.String(255), nullable=False), sa.Column("disposition", sa.String(24), nullable=False),
        sa.Column("previous_state", sa.String(64)), sa.Column("current_state", sa.String(64)),
        sa.Column("management_origin", sa.String(16), nullable=False, server_default="discovery"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["source_discovery_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["operation_id"], ["source_discovery_operations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("run_id", "source_key", name="uq_source_discovery_registrations_source"),
        sa.CheckConstraint("disposition IN ('created','existing_enabled','existing_disabled','existing_archived','conflict')", name="ck_source_discovery_registrations_disposition"),
    )
    op.create_index("ix_source_discovery_registrations_run", "source_discovery_registrations", ["run_id"])

    op.create_table(
        "continuous_acquisition_runs",
        *_common_run_columns(),
        sa.Column("snapshot_hash", sa.String(64), nullable=False, server_default=""), sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("lease_owner", sa.String(128)), sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("fencing_generation", sa.Integer(), nullable=False, server_default="0"), sa.Column("heartbeat_at", sa.DateTime(timezone=True)), sa.Column("deadline_at", sa.DateTime(timezone=True)),
        sa.Column("reserved_requests", sa.Integer(), nullable=False, server_default="0"), sa.Column("attempted_requests", sa.Integer(), nullable=False, server_default="0"), sa.Column("completed_requests", sa.Integer(), nullable=False, server_default="0"), sa.Column("truncated_requests", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("observed_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("created_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("duplicate_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("stale_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("invalid_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("conflict_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("terminal_code", sa.String(64)),
        sa.UniqueConstraint("slot_key", name="uq_continuous_acquisition_runs_slot_key"),
        sa.CheckConstraint("state IN ('completed','completed_empty','completed_partial','failed','indeterminate','planned','running')", name="ck_continuous_acquisition_runs_state"),
        sa.CheckConstraint("observed_count >= 0 AND created_count >= 0 AND duplicate_count >= 0 AND stale_count >= 0 AND invalid_count >= 0 AND conflict_count >= 0", name="ck_continuous_acquisition_runs_counts"),
    )
    op.create_index("ix_continuous_acquisition_runs_state", "continuous_acquisition_runs", ["state"])
    op.create_table(
        "continuous_acquisition_source_operations",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("run_id", sa.String(36), nullable=False), sa.Column("source_id", sa.String(36), nullable=False), sa.Column("source_snapshot_json", sa.JSON(), nullable=False), sa.Column("intent_state", sa.String(20), nullable=False), sa.Column("result_state", sa.String(20)), sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("page_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("byte_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("observed_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("created_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("duplicate_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("stale_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("invalid_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("conflict_count", sa.Integer(), nullable=False, server_default="0"), sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("continuation_evidence", sa.String(255)), sa.Column("result_code", sa.String(64)), sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["run_id"], ["continuous_acquisition_runs.id"], ondelete="RESTRICT"), sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="RESTRICT"), sa.UniqueConstraint("run_id", "source_id", name="uq_continuous_acquisition_source_operation"),
        sa.CheckConstraint("intent_state IN ('intent','succeeded','empty','failed','truncated','indeterminate')", name="ck_continuous_acquisition_source_operations_intent"), sa.CheckConstraint("result_state IS NULL OR result_state IN ('succeeded','empty','failed','truncated','indeterminate')", name="ck_continuous_acquisition_source_operations_result"), sa.CheckConstraint("observed_count >= 0 AND created_count >= 0 AND duplicate_count >= 0 AND stale_count >= 0 AND invalid_count >= 0 AND conflict_count >= 0", name="ck_continuous_acquisition_source_operations_counts"),
    )
    op.create_index("ix_continuous_acquisition_source_operations_run", "continuous_acquisition_source_operations", ["run_id"])
    op.create_index("ix_continuous_acquisition_source_operations_source", "continuous_acquisition_source_operations", ["source_id"])
    op.create_table(
        "continuous_acquisition_run_jobs",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("run_id", sa.String(36), nullable=False), sa.Column("operation_id", sa.String(36), nullable=False), sa.Column("job_id", sa.String(36), nullable=False), sa.Column("disposition", sa.String(16), nullable=False), sa.Column("provider_recency_at", sa.DateTime(timezone=True), nullable=False), sa.Column("recency_semantic", sa.String(64), nullable=False), sa.Column("freshness_policy_version", sa.String(64), nullable=False), sa.Column("identity_policy_version", sa.String(64), nullable=False), sa.Column("provenance_hash", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["continuous_acquisition_runs.id"], ondelete="RESTRICT"), sa.ForeignKeyConstraint(["operation_id"], ["continuous_acquisition_source_operations.id"], ondelete="RESTRICT"), sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"), sa.UniqueConstraint("run_id", "job_id", name="uq_continuous_acquisition_run_job"), sa.CheckConstraint("disposition IN ('created','duplicate')", name="ck_continuous_acquisition_run_jobs_disposition"),
    )
    op.create_index("ix_continuous_acquisition_run_jobs_run", "continuous_acquisition_run_jobs", ["run_id"])
    op.create_index("ix_continuous_acquisition_run_jobs_job", "continuous_acquisition_run_jobs", ["job_id"])
    op.create_table(
        "job_identity_keys",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("job_id", sa.String(36), nullable=False), sa.Column("identity_kind", sa.String(40), nullable=False), sa.Column("identity_version", sa.String(64), nullable=False), sa.Column("identity_value", sa.String(2048), nullable=False), sa.Column("value_digest", sa.String(64), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"), sa.UniqueConstraint("identity_version", "identity_kind", "identity_value", name="uq_job_identity_keys_strong"),
    )
    op.create_index("ix_job_identity_keys_job", "job_identity_keys", ["job_id"])
    op.create_index("ix_job_identity_keys_digest", "job_identity_keys", ["value_digest"])

    # Deterministic backfill of only unambiguous source/external identities.
    rows = connection.execute(sa.text("SELECT job_id, source_id, external_id FROM job_source_references WHERE external_id IS NOT NULL ORDER BY id")).mappings()
    seen: dict[str, str] = {}
    for row in rows:
        source = connection.execute(sa.text("SELECT source_key FROM sources WHERE id=:id"), {"id": row["source_id"]}).scalar()
        if source is None:
            continue
        value = f"{source}:{row['external_id']}"
        owner = seen.get(value)
        if owner is not None and owner != row["job_id"]:
            raise RuntimeError(f"identity_backfill_collision:{value}:{owner}:{row['job_id']}")
        seen[value] = str(row["job_id"])
        digest = hashlib.sha256(value.encode()).hexdigest()
        connection.execute(sa.text("INSERT INTO job_identity_keys (id,job_id,identity_kind,identity_version,identity_value,value_digest,created_at) VALUES (lower(hex(randomblob(16))),:job,'source_external_id','strong-identity-v1',:value,:digest,CURRENT_TIMESTAMP)"), {"job": row["job_id"], "value": value, "digest": digest})


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F10.1B migration currently supports SQLite only")
    for index, table in (("ix_job_identity_keys_digest", "job_identity_keys"), ("ix_job_identity_keys_job", "job_identity_keys"), ("ix_continuous_acquisition_run_jobs_job", "continuous_acquisition_run_jobs"), ("ix_continuous_acquisition_run_jobs_run", "continuous_acquisition_run_jobs"), ("ix_continuous_acquisition_source_operations_source", "continuous_acquisition_source_operations"), ("ix_continuous_acquisition_source_operations_run", "continuous_acquisition_source_operations"), ("ix_continuous_acquisition_runs_state", "continuous_acquisition_runs"), ("ix_source_discovery_operations_run", "source_discovery_operations"), ("ix_source_discovery_registrations_run", "source_discovery_registrations"), ("ix_source_discovery_runs_state", "source_discovery_runs")):
        op.drop_index(index, table_name=table)
    for table in ("job_identity_keys", "continuous_acquisition_run_jobs", "continuous_acquisition_source_operations", "continuous_acquisition_runs", "source_discovery_registrations", "source_discovery_operations", "source_discovery_runs"):
        op.drop_table(table)
