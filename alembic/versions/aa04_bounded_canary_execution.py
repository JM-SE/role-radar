"""Persist immutable canary ceilings and resumable stage checkpoints."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "aa04_bounded_canary_execution"
down_revision: str | None = "aa03_reconcile_legacy_campaign_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("job_search_runs") as batch:
        batch.add_column(sa.Column("canary_budget_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("canary_checkpoint_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("job_search_runs") as batch:
        batch.drop_column("canary_checkpoint_json")
        batch.drop_column("canary_budget_json")
