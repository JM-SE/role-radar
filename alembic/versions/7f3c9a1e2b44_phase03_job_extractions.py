"""phase03_job_extractions — extracción estructurada durable."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "7f3c9a1e2b44"
down_revision: str | None = "2c5a1f9d3e70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "job_extractions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("model_capability", sa.String(length=64), nullable=False),
        sa.Column("model_identifier", sa.String(length=255), nullable=True),
        sa.Column("broker_task_id", sa.String(length=128), nullable=True),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("extraction_json", sa.JSON(), nullable=True),
        sa.Column("validation_status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_class", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("finish_reason", sa.String(length=32), nullable=True),
        sa.Column("usage_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "job_id", "input_hash", "schema_version", "prompt_version",
            name="uq_job_extractions_operation",
        ),
    )
    op.create_index("ix_job_extractions_job_id", "job_extractions", ["job_id"], unique=False)
    op.create_index(
        "ix_job_extractions_broker_task_id", "job_extractions", ["broker_task_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_job_extractions_broker_task_id", table_name="job_extractions")
    op.drop_index("ix_job_extractions_job_id", table_name="job_extractions")
    op.drop_table("job_extractions")
