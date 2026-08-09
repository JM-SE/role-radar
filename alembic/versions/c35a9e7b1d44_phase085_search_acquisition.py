"""F8.5 Brave/Tavily acquisition budgets, calls and 24h memos."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c35a9e7b1d44"
down_revision: str | None = "48213cabbd50"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.5 acquisition migration currently supports SQLite only")

    op.create_table(
        "acquisition_budget_periods",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("tier", sa.String(16), nullable=False),
        sa.Column("utc_month", sa.String(7), nullable=False),
        sa.Column("config_version", sa.String(64), nullable=False),
        sa.Column("unit_limit", sa.Integer(), nullable=False),
        sa.Column("units_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("units_reserved", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("micro_usd_limit", sa.Integer(), nullable=False),
        sa.Column("micro_usd_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("micro_usd_reserved", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider", "tier", "utc_month", name="uq_acquisition_budget_period"),
        sa.CheckConstraint("provider IN ('brave','tavily')", name="ck_acquisition_budget_provider"),
        sa.CheckConstraint("tier IN ('free','paid')", name="ck_acquisition_budget_tier"),
        sa.CheckConstraint(
            "unit_limit >= 0 AND units_used >= 0 AND units_reserved >= 0 "
            "AND micro_usd_limit >= 0 AND micro_usd_used >= 0 AND micro_usd_reserved >= 0",
            name="ck_acquisition_budget_nonnegative",
        ),
        sa.CheckConstraint(
            "units_used + units_reserved <= unit_limit", name="ck_acquisition_budget_units"
        ),
        sa.CheckConstraint(
            "micro_usd_used + micro_usd_reserved <= micro_usd_limit",
            name="ck_acquisition_budget_micro_usd",
        ),
    )
    op.create_index(
        "ix_acquisition_budget_period_month", "acquisition_budget_periods", ["utc_month"]
    )

    op.create_table(
        "acquisition_reservations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("operation_key", sa.String(512), nullable=False),
        sa.Column("period_id", sa.String(36), nullable=False),
        sa.Column("units_reserved", sa.Integer(), nullable=False),
        sa.Column("micro_usd_reserved", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="reserved"),
        sa.Column("transmission_status", sa.String(16), nullable=False, server_default="not_sent"),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["period_id"], ["acquisition_budget_periods.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("operation_key", name="uq_acquisition_reservation_operation"),
        sa.CheckConstraint(
            "units_reserved >= 0 AND micro_usd_reserved >= 0",
            name="ck_acquisition_reservation_nonnegative",
        ),
        sa.CheckConstraint(
            "status IN ('reserved','spent','released')", name="ck_acquisition_reservation_status"
        ),
        sa.CheckConstraint(
            "transmission_status IN ('not_sent','sent','indeterminate')",
            name="ck_acquisition_reservation_transmission",
        ),
    )
    op.create_index(
        "ix_acquisition_reservations_period_status",
        "acquisition_reservations",
        ["period_id", "status"],
    )

    op.create_table(
        "provider_call_ledger",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(255), nullable=False),
        sa.Column("operation_key", sa.String(512), nullable=False),
        sa.Column("cycle_id", sa.String(36), nullable=False),
        sa.Column("query_key", sa.String(128), nullable=False),
        sa.Column("query_ordinal", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("tier", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("known_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unknown_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rejected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("reservation_id", sa.String(36), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["reservation_id"], ["acquisition_reservations.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("operation_key", name="uq_provider_call_ledger_operation"),
        sa.CheckConstraint("provider IN ('brave','tavily')", name="ck_provider_call_provider"),
        sa.CheckConstraint("tier IN ('free','paid')", name="ck_provider_call_tier"),
        sa.CheckConstraint(
            "status IN ('succeeded','empty','failed','malformed','indeterminate','reserved')",
            name="ck_provider_call_status",
        ),
        sa.CheckConstraint(
            "candidate_count >= 0 AND known_count >= 0 AND unknown_count >= 0 "
            "AND rejected_count >= 0",
            name="ck_provider_call_counts",
        ),
    )
    op.create_index(
        "ix_provider_call_ledger_cycle_query", "provider_call_ledger", ["cycle_id", "query_ordinal"]
    )
    op.create_index("ix_provider_call_ledger_status", "provider_call_ledger", ["status"])

    op.create_table(
        "discovery_query_memos",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("tier", sa.String(16), nullable=False),
        sa.Column("query_key", sa.String(128), nullable=False),
        sa.Column("planner_version", sa.String(64), nullable=False),
        sa.Column("query_version", sa.String(64), nullable=False),
        sa.Column("config_version", sa.String(64), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("known_count", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "provider",
            "tier",
            "query_key",
            "planner_version",
            "query_version",
            "config_version",
            name="uq_discovery_query_memo_identity",
        ),
        sa.CheckConstraint("provider IN ('brave','tavily')", name="ck_discovery_memo_provider"),
        sa.CheckConstraint("tier IN ('free','paid')", name="ck_discovery_memo_tier"),
        sa.CheckConstraint("status IN ('succeeded','empty')", name="ck_discovery_memo_status"),
        sa.CheckConstraint(
            "candidate_count >= 0 AND known_count >= 0", name="ck_discovery_memo_counts"
        ),
    )
    op.create_index("ix_discovery_query_memos_expiry", "discovery_query_memos", ["expires_at"])


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.5 acquisition migration currently supports SQLite only")
    # Foreign-key-safe and deliberately refuse to destroy durable accounting.
    for table in (
        "provider_call_ledger",
        "discovery_query_memos",
        "acquisition_reservations",
        "acquisition_budget_periods",
    ):
        if connection.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("acquisition_downgrade_aborted: durable accounting would be lost")
    op.drop_index("ix_discovery_query_memos_expiry", table_name="discovery_query_memos")
    op.drop_table("discovery_query_memos")
    op.drop_index("ix_provider_call_ledger_status", table_name="provider_call_ledger")
    op.drop_index("ix_provider_call_ledger_cycle_query", table_name="provider_call_ledger")
    op.drop_table("provider_call_ledger")
    op.drop_index(
        "ix_acquisition_reservations_period_status", table_name="acquisition_reservations"
    )
    op.drop_table("acquisition_reservations")
    op.drop_index("ix_acquisition_budget_period_month", table_name="acquisition_budget_periods")
    op.drop_table("acquisition_budget_periods")
