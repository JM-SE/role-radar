"""F8.6 Jobicy free-source durable poll state."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d8f6a1b2c3d4"
down_revision: str | None = "c35a9e7b1d44"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.6 poll-state migration currently supports SQLite only")
    op.create_table(
        "source_poll_states",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("cadence_version", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_reserved_slot", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_request_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reservation_id", sa.String(128), nullable=True),
        sa.Column("operation_id", sa.String(512), nullable=True),
        sa.Column("etag", sa.String(255), nullable=True),
        sa.Column("last_modified", sa.String(255), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("source_id", name="uq_source_poll_states_source_id"),
        sa.CheckConstraint("revision >= 1", name="ck_source_poll_states_revision"),
        sa.CheckConstraint(
            "last_reserved_slot IS NULL OR last_reserved_slot <= next_due_at",
            name="ck_source_poll_states_reserved_slot_order",
        ),
    )
    op.create_index("ix_source_poll_states_due", "source_poll_states", ["next_due_at", "source_id"])
    connection.execute(
        sa.text(
            "INSERT INTO source_poll_states "
            "(id, source_id, cadence_version, policy_version, next_due_at, revision, "
            "created_at, updated_at) "
            "SELECT lower(hex(randomblob(16))), id, 'jobicy-hourly-v1', 'jobicy-latam-v1', "
            "created_at, 1, created_at, created_at FROM sources"
        )
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.6 poll-state migration currently supports SQLite only")
    active = connection.execute(
        sa.text(
            "SELECT 1 FROM source_poll_states WHERE last_reserved_slot IS NOT NULL "
            "OR last_request_at IS NOT NULL OR last_success_at IS NOT NULL "
            "OR reservation_id IS NOT NULL OR operation_id IS NOT NULL LIMIT 1"
        )
    ).first()
    if active:
        raise RuntimeError("poll_state_downgrade_aborted: durable poll activity would be lost")
    op.drop_index("ix_source_poll_states_due", table_name="source_poll_states")
    op.drop_table("source_poll_states")
