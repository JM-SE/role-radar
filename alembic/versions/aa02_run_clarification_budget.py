"""Persist a single run-wide description-clarification budget."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "aa02_run_clarification_budget"
down_revision: str | None = "aa01_source_activation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Run clarification budget migration currently supports SQLite only")
    op.add_column(
        "job_search_runs",
        sa.Column("clarification_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    with op.batch_alter_table("job_search_runs") as batch:
        batch.create_check_constraint(
            "ck_job_search_runs_clarification_attempts", "clarification_attempts >= 0"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Run clarification budget migration currently supports SQLite only")
    with op.batch_alter_table("job_search_runs") as batch:
        batch.drop_constraint("ck_job_search_runs_clarification_attempts", type_="check")
        batch.drop_column("clarification_attempts")
