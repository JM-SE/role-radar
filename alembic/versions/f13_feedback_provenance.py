"""Persist full feedback provenance on feedback decisions.

Revision ID: f13_feedback_provenance
Revises: f12_profile_first_mvp
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f13_feedback_provenance"
down_revision: str | None = "f12_profile_first_mvp"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Feedback provenance migration currently supports SQLite only")
    with op.batch_alter_table("feedback_decisions") as batch:
        batch.add_column(sa.Column("profile_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("row_version", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("schema_version", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("canonical_profile_sha256", sa.String(64), nullable=True))
        batch.add_column(sa.Column("policy_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("relevance_version", sa.String(64), nullable=True))
        batch.add_column(sa.Column("text_sha256", sa.String(64), nullable=True))
        batch.add_column(sa.Column("reviewer", sa.String(64), nullable=True))


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        raise RuntimeError("Feedback provenance migration currently supports SQLite only")
    with op.batch_alter_table("feedback_decisions") as batch:
        batch.drop_column("reviewer")
        batch.drop_column("text_sha256")
        batch.drop_column("relevance_version")
        batch.drop_column("policy_hash")
        batch.drop_column("canonical_profile_sha256")
        batch.drop_column("schema_version")
        batch.drop_column("row_version")
        batch.drop_column("profile_id")
