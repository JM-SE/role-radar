"""Bounded source activation campaigns."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "aa01_source_activation"
down_revision: str | None = "f13_feedback_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "source_activation_campaigns",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "profile_id",
            sa.String(36),
            sa.ForeignKey("candidate_profiles.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('active','paused','completed')", name="ck_activation_campaign_status"
        ),
        sa.CheckConstraint("batch_size > 0", name="ck_activation_campaign_batch_size"),
    )
    op.create_index("ix_activation_campaigns_status", "source_activation_campaigns", ["status"])
    op.create_table(
        "source_activation_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.String(36),
            sa.ForeignKey("source_activation_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("sources.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("failure_streak", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("no_signal_streak", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_selected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_run_id",
            sa.String(36),
            sa.ForeignKey("job_search_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.CheckConstraint("role IN ('baseline','managed')", name="ck_activation_member_role"),
        sa.CheckConstraint(
            "state IN ('pending','retained')", name="ck_activation_member_state"
        ),
        sa.CheckConstraint(
            "failure_streak >= 0 AND no_signal_streak >= 0",
            name="ck_activation_member_streaks",
        ),
        sa.UniqueConstraint("campaign_id", "source_id", name="uq_activation_member_source"),
        sa.UniqueConstraint("campaign_id", "ordinal", name="uq_activation_member_ordinal"),
    )
    op.create_index(
        "ix_activation_members_campaign_state",
        "source_activation_members",
        ["campaign_id", "state"],
    )
    op.add_column(
        "job_search_runs",
        sa.Column("activation_campaign_id", sa.String(36), nullable=True),
    )
    op.add_column(
        "job_search_runs",
        sa.Column("campaign_finalized_at", sa.DateTime(timezone=True), nullable=True),
    )
    with op.batch_alter_table("job_search_runs", recreate="always") as batch:
        batch.create_foreign_key(
            "fk_runs_activation_campaign",
            "source_activation_campaigns",
            ["activation_campaign_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_job_search_runs_activation_campaign", ["activation_campaign_id"])


def downgrade() -> None:
    with op.batch_alter_table("job_search_runs", recreate="always") as batch:
        batch.drop_index("ix_job_search_runs_activation_campaign")
        batch.drop_constraint("fk_runs_activation_campaign", type_="foreignkey")
        batch.drop_column("campaign_finalized_at")
        batch.drop_column("activation_campaign_id")
    op.drop_index("ix_activation_members_campaign_state", table_name="source_activation_members")
    op.drop_table("source_activation_members")
    op.drop_index("ix_activation_campaigns_status", table_name="source_activation_campaigns")
    op.drop_table("source_activation_campaigns")
