"""phase02_job_description_hash — índice para deduplicación D6.

Revision ID: 2c5a1f9d3e70
Revises: 0f1babe12f06
Create Date: 2026-08-01
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "2c5a1f9d3e70"
down_revision: str | None = "0f1babe12f06"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("description_hash", sa.String(length=64), nullable=True))
    op.create_index("ix_jobs_description_hash", "jobs", ["description_hash"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_jobs_description_hash", table_name="jobs")
    op.drop_column("jobs", "description_hash")
