"""F8.4 durable discovery foundation.

The migration deliberately stores only cycle/query aggregates and HMAC query
identities.  Search result payloads and plaintext queries have no database
representation.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "48213cabbd50"
down_revision: str | None = "b8c1d4e6f901"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.4 discovery migration currently supports SQLite only")

    # Audit before DDL.  Existing rows must be projectable without guessing.
    bad_sources = connection.execute(
        sa.text(
            "SELECT id FROM sources WHERE configuration IS NOT NULL AND json_valid(configuration)=0"
        )
    ).all()
    if bad_sources:
        raise RuntimeError("discovery_migration_aborted: invalid source configuration JSON")

    op.add_column(
        "job_search_runs",
        sa.Column("discovery_mode", sa.String(length=16), nullable=False, server_default="none"),
    )
    connection.execute(
        sa.text(
            "UPDATE job_search_runs SET discovery_mode='none' "
            "WHERE discovery_mode IS NULL OR discovery_mode NOT IN ('none','scheduled_due')"
        )
    )
    with op.batch_alter_table("job_search_runs") as batch:
        batch.create_check_constraint(
            "ck_job_search_runs_discovery_mode", "discovery_mode IN ('none','scheduled_due')"
        )

    op.add_column(
        "sources",
        sa.Column("management_origin", sa.String(16), nullable=False, server_default="manual"),
    )
    op.add_column("sources", sa.Column("discovery_policy_version", sa.String(64), nullable=True))
    op.add_column(
        "sources", sa.Column("discovery_verified_at", sa.DateTime(timezone=True), nullable=True)
    )
    connection.execute(
        sa.text("UPDATE sources SET management_origin='manual' WHERE management_origin IS NULL")
    )
    with op.batch_alter_table("sources") as batch:
        batch.create_check_constraint(
            "ck_sources_management_origin", "management_origin IN ('manual','discovery')"
        )
        batch.create_check_constraint(
            "ck_sources_discovery_metadata",
            "management_origin='manual' OR "
            "(discovery_policy_version IS NOT NULL AND discovery_verified_at IS NOT NULL)",
        )
        batch.create_index(
            "ix_sources_management_enabled_archived",
            ["management_origin", "enabled", "archived_at"],
        )

    op.create_table(
        "discovery_cycles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("reused_from_cycle_id", sa.String(36), nullable=True),
        sa.Column("profile_snapshot_json", sa.JSON(), nullable=False),
        sa.Column("planner_version", sa.String(64), nullable=False),
        sa.Column("planner_hash", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("stats_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("planned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["run_id"], ["job_search_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["reused_from_cycle_id"], ["discovery_cycles.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("run_id", name="uq_discovery_cycles_run_id"),
        sa.CheckConstraint(
            "status IN ('planned','running','completed','degraded','failed','reused')",
            name="ck_discovery_cycles_status",
        ),
    )
    op.create_index("ix_discovery_cycles_reuse", "discovery_cycles", ["reused_from_cycle_id"])
    op.create_index("ix_discovery_cycles_status", "discovery_cycles", ["status"])

    op.create_table(
        "discovery_queries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("cycle_id", sa.String(36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("family", sa.String(64), nullable=False),
        sa.Column("query_key", sa.String(64), nullable=False),
        sa.Column("provider_intent", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("known_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("verified_count", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["cycle_id"], ["discovery_cycles.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("cycle_id", "ordinal", name="uq_discovery_queries_cycle_ordinal"),
        sa.UniqueConstraint(
            "cycle_id", "query_key", "provider_intent", name="uq_discovery_queries_identity"
        ),
        sa.CheckConstraint(
            "status IN ('planned','executed','empty','failed','reused')",
            name="ck_discovery_queries_status",
        ),
        sa.CheckConstraint("ordinal >= 0 AND ordinal < 24", name="ck_discovery_queries_ordinal"),
        sa.CheckConstraint(
            "candidate_count >= 0 AND known_count >= 0 AND unknown_count >= 0 "
            "AND rejected_count >= 0 AND verified_count >= 0",
            name="ck_discovery_queries_counts",
        ),
    )
    op.create_index(
        "ix_discovery_queries_cycle_ordinal", "discovery_queries", ["cycle_id", "ordinal"]
    )
    op.create_index("ix_discovery_queries_query_key", "discovery_queries", ["query_key"])


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.4 discovery migration currently supports SQLite only")
    has_data = connection.execute(sa.text("SELECT 1 FROM discovery_cycles LIMIT 1")).first()
    if has_data:
        raise RuntimeError("discovery_downgrade_aborted: discovery data would be lost")
    op.drop_index("ix_discovery_queries_query_key", table_name="discovery_queries")
    op.drop_index("ix_discovery_queries_cycle_ordinal", table_name="discovery_queries")
    op.drop_table("discovery_queries")
    op.drop_index("ix_discovery_cycles_status", table_name="discovery_cycles")
    op.drop_index("ix_discovery_cycles_reuse", table_name="discovery_cycles")
    op.drop_table("discovery_cycles")
    with op.batch_alter_table("sources") as batch:
        batch.drop_index("ix_sources_management_enabled_archived")
        batch.drop_constraint("ck_sources_discovery_metadata", type_="check")
        batch.drop_constraint("ck_sources_management_origin", type_="check")
        batch.drop_column("discovery_verified_at")
        batch.drop_column("discovery_policy_version")
        batch.drop_column("management_origin")
    with op.batch_alter_table("job_search_runs") as batch:
        batch.drop_constraint("ck_job_search_runs_discovery_mode", type_="check")
        batch.drop_column("discovery_mode")
