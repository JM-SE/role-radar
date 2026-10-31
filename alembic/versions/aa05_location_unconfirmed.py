"""Keep geography-uncertain intake in a separate review-only table."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "aa05_location_unconfirmed"
down_revision: str | None = "aa04_bounded_canary_execution"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "location_unconfirmed",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("profile_id", sa.String(36), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("profile_schema_version", sa.Integer(), nullable=False),
        sa.Column("profile_hash", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("external_id", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("company", sa.String(255), nullable=False),
        sa.Column("location", sa.String(255), nullable=True),
        sa.Column("source_url", sa.String(2048), nullable=True),
        sa.Column("application_url", sa.String(2048), nullable=False),
        sa.Column("reason_code", sa.String(32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("profile_version > 0", name="ck_location_unconfirmed_profile_version"),
        sa.CheckConstraint(
            "profile_schema_version > 0",
            name="ck_location_unconfirmed_profile_schema_version",
        ),
        sa.CheckConstraint(
            "length(profile_hash) = 64", name="ck_location_unconfirmed_profile_hash_length"
        ),
        sa.CheckConstraint(
            "length(trim(external_id)) > 0", name="ck_location_unconfirmed_external_id"
        ),
        sa.CheckConstraint("length(trim(title)) > 0", name="ck_location_unconfirmed_title"),
        sa.CheckConstraint("length(trim(company)) > 0", name="ck_location_unconfirmed_company"),
        sa.CheckConstraint(
            "length(trim(application_url)) > 0",
            name="ck_location_unconfirmed_application_url",
        ),
        sa.CheckConstraint(
            "reason_code = 'region_unknown'", name="ck_location_unconfirmed_reason_code"
        ),
        sa.ForeignKeyConstraint(
            ["profile_id"],
            ["candidate_profiles.id"],
            name="fk_location_unconfirmed_profile",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name="fk_location_unconfirmed_source",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "profile_id",
            "source_id",
            "external_id",
            name="uq_location_unconfirmed_profile_source_external",
        ),
    )
    op.create_index(
        "ix_location_unconfirmed_profile_binding_last_seen",
        "location_unconfirmed",
        [
            "profile_id",
            "profile_version",
            "profile_schema_version",
            "profile_hash",
            "last_seen_at",
        ],
        unique=False,
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.scalar(sa.text("SELECT 1 FROM location_unconfirmed LIMIT 1")) is not None:
        raise RuntimeError("location_unconfirmed_not_empty")
    op.drop_index(
        "ix_location_unconfirmed_profile_binding_last_seen",
        table_name="location_unconfirmed",
    )
    op.drop_table("location_unconfirmed")
