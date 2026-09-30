"""Retire legacy source activation thresholds and member states."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "aa03_reconcile_legacy_campaign_schema"
down_revision: str | None = "aa02_run_clarification_budget"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Source activation reconciliation currently supports SQLite only")

    inspector = sa.inspect(op.get_bind())
    campaign_columns = {
        column["name"] for column in inspector.get_columns("source_activation_campaigns")
    }
    retired = {"max_failure_streak", "max_no_signal_streak"} & campaign_columns
    if retired:
        campaign_checks = {
            check["name"]
            for check in inspector.get_check_constraints("source_activation_campaigns")
        }
        retired_checks = {
            "ck_activation_campaign_failure_limit",
            "ck_activation_campaign_signal_limit",
        } & campaign_checks
        with op.batch_alter_table("source_activation_campaigns", recreate="always") as batch:
            for constraint in sorted(retired_checks):
                batch.drop_constraint(constraint, type_="check")
            for column in sorted(retired):
                batch.drop_column(column)

    member_sql = op.get_bind().exec_driver_sql(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='source_activation_members'"
    ).scalar_one()
    if "disabled_failure" in member_sql or "disabled_no_signal" in member_sql:
        op.get_bind().exec_driver_sql(
            "UPDATE source_activation_members SET state='retained' "
            "WHERE state IN ('disabled_failure','disabled_no_signal')"
        )
        with op.batch_alter_table("source_activation_members", recreate="always") as batch:
            batch.drop_constraint("ck_activation_member_state", type_="check")
            batch.create_check_constraint(
                "ck_activation_member_state", "state IN ('pending','retained')"
            )


def downgrade() -> None:
    raise RuntimeError(
        "Cannot downgrade: retired threshold values and legacy member states were discarded"
    )
