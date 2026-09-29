"""Allow preliminary-only profile-first notification items.

Revision ID: f12_profile_first_mvp
Revises: f11_feedback
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f12_profile_first_mvp"
down_revision: str | None = "f11_feedback"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Profile-first migration currently supports SQLite only")
    with op.batch_alter_table("notification_items") as batch:
        batch.alter_column(
            "deep_evaluation_id",
            existing_type=sa.String(length=36),
            nullable=True,
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Profile-first migration currently supports SQLite only")
    with op.batch_alter_table("notification_items") as batch:
        batch.alter_column(
            "deep_evaluation_id",
            existing_type=sa.String(length=36),
            nullable=False,
        )
