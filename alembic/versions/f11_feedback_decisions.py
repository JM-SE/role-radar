"""Current product feedback decisions (append-only human revisions).

This revision is intentionally additive.  It creates one table and drops it
on downgrade; no existing row is rewritten.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f11_feedback"
down_revision: str | None = "f101b_continuous"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("Feedback decisions migration currently supports SQLite only")

    op.create_table(
        "feedback_decisions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(16), nullable=False),
        sa.Column("primary_reason", sa.String(64), nullable=False),
        sa.Column("secondary_reasons_json", sa.JSON(), nullable=False),
        sa.Column("note", sa.String(512), nullable=True),
        sa.Column("relevance_band", sa.String(16), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["job_search_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("run_id", "job_id", "revision", name="uq_feedback_decisions_revision"),
        sa.CheckConstraint(
            "label IN ('apply','maybe','reject')", name="ck_feedback_decisions_label"
        ),
        sa.CheckConstraint("revision > 0", name="ck_feedback_decisions_revision"),
    )
    op.create_index("ix_feedback_decisions_run_job", "feedback_decisions", ["run_id", "job_id"])


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("Feedback decisions migration currently supports SQLite only")
    op.drop_index("ix_feedback_decisions_run_job", table_name="feedback_decisions")
    op.drop_table("feedback_decisions")
