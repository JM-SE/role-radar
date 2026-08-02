"""phase07 durable Telegram digest outbox."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "7f0a4c2d9e11"
down_revision: str | None = "577682b6d35a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "job_search_runs",
        sa.Column("notification_mode", sa.String(16), nullable=False, server_default="none"),
    )
    op.add_column("job_search_runs", sa.Column("schedule_slot", sa.String(64), nullable=True))
    op.create_index("ix_job_search_runs_schedule_slot", "job_search_runs", ["schedule_slot"])
    op.create_table(
        "notification_batches",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("schedule_slot", sa.String(64), nullable=False),
        sa.Column("channel", sa.String(24), nullable=False, server_default="telegram"),
        sa.Column("recipient_key_hash", sa.String(64), nullable=False),
        sa.Column("operation_key", sa.String(512), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("formatter_version", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("body_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("body_length", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sending_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("telegram_message_id", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["job_search_runs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_key", name="uq_notification_batches_operation_key"),
        sa.CheckConstraint(
            "item_count >= 1 AND item_count <= 5", name="ck_notification_batch_item_count"
        ),
    )
    op.create_index("ix_notification_batches_run", "notification_batches", ["run_id"])
    op.create_index(
        "ix_notification_batches_due", "notification_batches", ["status", "next_attempt_at"]
    )
    op.create_table(
        "notification_items",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("batch_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("channel", sa.String(24), nullable=False, server_default="telegram"),
        sa.Column("recipient_key_hash", sa.String(64), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("job_score_id", sa.String(36), nullable=False),
        sa.Column("deep_evaluation_id", sa.String(36), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="reserved"),
        sa.Column("outcome_code", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["batch_id"], ["notification_batches.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["run_id"], ["job_search_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_score_id"], ["job_scores.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["deep_evaluation_id"], ["job_deep_evaluations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("batch_id", "rank", name="uq_notification_items_batch_rank"),
        sa.UniqueConstraint("batch_id", "job_id", name="uq_notification_items_batch_job"),
        sa.UniqueConstraint(
            "channel", "recipient_key_hash", "job_id", name="uq_notification_items_global_job"
        ),
        sa.CheckConstraint("rank >= 1 AND rank <= 5", name="ck_notification_item_rank"),
    )
    op.create_index("ix_notification_items_run", "notification_items", ["run_id"])
    op.create_index("ix_notification_items_batch", "notification_items", ["batch_id"])
    op.create_index("ix_notification_items_job", "notification_items", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_notification_items_job", table_name="notification_items")
    op.drop_index("ix_notification_items_batch", table_name="notification_items")
    op.drop_index("ix_notification_items_run", table_name="notification_items")
    op.drop_table("notification_items")
    op.drop_index("ix_notification_batches_due", table_name="notification_batches")
    op.drop_index("ix_notification_batches_run", table_name="notification_batches")
    op.drop_table("notification_batches")
    op.drop_index("ix_job_search_runs_schedule_slot", table_name="job_search_runs")
    op.drop_column("job_search_runs", "schedule_slot")
    op.drop_column("job_search_runs", "notification_mode")
