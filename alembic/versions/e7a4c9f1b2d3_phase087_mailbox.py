"""F8.7 provider-neutral mailbox state, receipts and link intake."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e7a4c9f1b2d3"
down_revision: str | None = "d8f6a1b2c3d4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.7 mailbox migration currently supports SQLite only")
    op.create_table(
        "mailbox_states",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("uidvalidity", sa.Integer(), nullable=True),
        sa.Column("highest_terminal_uid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_reserved_slot", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reservation_id", sa.String(128), nullable=True),
        sa.Column("operation_id", sa.String(512), nullable=True),
        sa.Column("last_request_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_error_code", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("source_id", name="uq_mailbox_states_source_id"),
        sa.CheckConstraint("highest_terminal_uid >= 0", name="ck_mailbox_states_uid"),
        sa.CheckConstraint("revision >= 1", name="ck_mailbox_states_revision"),
    )
    op.create_index("ix_mailbox_states_due", "mailbox_states", ["next_due_at", "source_id"])
    op.create_table(
        "email_receipts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("uidvalidity", sa.Integer(), nullable=False),
        sa.Column("uid", sa.Integer(), nullable=False),
        sa.Column("message_id_hmac", sa.String(128), nullable=True),
        sa.Column("content_hmac", sa.String(128), nullable=True),
        sa.Column("hmac_version", sa.String(32), nullable=False, server_default="hmac-v1"),
        sa.Column("parser_name", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("parser_version", sa.String(64), nullable=False, server_default="1"),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("sender_domain", sa.String(255), nullable=True),
        sa.Column("list_id", sa.String(255), nullable=True),
        sa.Column("auth_evidence", sa.String(16), nullable=False, server_default="missing"),
        sa.Column("template_code", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("proposal_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("source_id", "uidvalidity", "uid", name="uq_email_receipts_cursor"),
        sa.CheckConstraint("uid > 0", name="ck_email_receipts_uid"),
        sa.CheckConstraint(
            "status IN ('succeeded','review','quarantine','limit','malformed',"
            "'unsupported','failed')",
            name="ck_email_receipts_status",
        ),
    )
    op.create_index("ix_email_receipts_content_hmac", "email_receipts", ["content_hmac"])
    op.create_table(
        "email_link_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("url_hmac", sa.String(128), nullable=False),
        sa.Column("normalized_url", sa.String(2048), nullable=True),
        sa.Column("parser_name", sa.String(64), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=True),
        sa.Column("job_source_reference_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["receipt_id"], ["email_receipts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["job_source_reference_id"], ["job_source_references.id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "status IN ('intake','review','quarantine','verified','rejected')",
            name="ck_email_proposals_status",
        ),
        sa.CheckConstraint(
            "kind IN ('ats_direct','link','message')", name="ck_email_proposals_kind"
        ),
    )
    op.create_index("ix_email_link_proposals_receipt", "email_link_proposals", ["receipt_id"])


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        raise RuntimeError("F8.7 mailbox migration currently supports SQLite only")
    active = connection.execute(
        sa.text(
            "SELECT 1 FROM mailbox_states "
            "WHERE uidvalidity IS NOT NULL OR highest_terminal_uid > 0 LIMIT 1"
        )
    ).first()
    receipts = connection.execute(sa.text("SELECT 1 FROM email_receipts LIMIT 1")).first()
    if active or receipts:
        raise RuntimeError("mailbox_downgrade_aborted: durable mailbox activity would be lost")
    op.drop_index("ix_email_link_proposals_receipt", table_name="email_link_proposals")
    op.drop_table("email_link_proposals")
    op.drop_index("ix_email_receipts_content_hmac", table_name="email_receipts")
    op.drop_table("email_receipts")
    op.drop_index("ix_mailbox_states_due", table_name="mailbox_states")
    op.drop_table("mailbox_states")
