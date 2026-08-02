"""phase04_matching — canonical profiles and immutable job scores."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8a4d2f6c9b10"
down_revision: str | None = "7f3c9a1e2b44"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("candidate_profiles", sa.Column("schema_version", sa.Integer(), nullable=True))
    connection = op.get_bind()
    rows = (
        connection.execute(
            sa.text(
                "SELECT id, name, version, created_at "
                "FROM candidate_profiles ORDER BY created_at, id"
            )
        )
        .mappings()
        .all()
    )
    seen: dict[tuple[str, int], int] = {}
    for row in rows:
        original = int(row["version"])
        key = (str(row["name"]), original)
        if key in seen:
            seen[key] += 1
            new_version = max(original, seen[key])
            while (str(row["name"]), new_version) in seen:
                new_version += 1
            connection.execute(
                sa.text(
                    "UPDATE candidate_profiles SET version=:version, schema_version=0 WHERE id=:id"
                ),
                {"version": new_version, "id": row["id"]},
            )
            seen[(str(row["name"]), new_version)] = 1
        else:
            seen[key] = 1
            connection.execute(
                sa.text("UPDATE candidate_profiles SET schema_version=0 WHERE id=:id"),
                {"id": row["id"]},
            )
    with op.batch_alter_table("candidate_profiles") as batch:
        batch.alter_column("schema_version", existing_type=sa.Integer(), nullable=False)
        batch.create_unique_constraint("uq_candidate_profiles_name_version", ["name", "version"])

    op.create_table(
        "job_scores",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("profile_id", sa.String(length=36), nullable=False),
        sa.Column("extraction_id", sa.String(length=36), nullable=True),
        sa.Column("operation_key", sa.String(length=512), nullable=False),
        sa.Column("scoring_version", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("preliminary_score", sa.Integer(), nullable=False),
        sa.Column("eligible", sa.Boolean(), nullable=False),
        sa.Column("signal_json", sa.JSON(), nullable=False),
        sa.Column("hard_blocker_json", sa.JSON(), nullable=False),
        sa.Column("ambiguity_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "preliminary_score >= 0 AND preliminary_score <= 100", name="ck_job_scores_score_range"
        ),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["profile_id"], ["candidate_profiles.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["extraction_id"], ["job_extractions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_key", name="uq_job_scores_operation_key"),
    )
    op.create_index("ix_job_scores_job_id", "job_scores", ["job_id"])
    op.create_index("ix_job_scores_profile_id", "job_scores", ["profile_id"])
    op.create_index("ix_job_scores_extraction_id", "job_scores", ["extraction_id"])
    op.create_index("ix_job_scores_input_hash", "job_scores", ["input_hash"])
    op.create_index("ix_job_scores_latest", "job_scores", ["job_id", "profile_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_job_scores_latest", table_name="job_scores")
    op.drop_index("ix_job_scores_input_hash", table_name="job_scores")
    op.drop_index("ix_job_scores_extraction_id", table_name="job_scores")
    op.drop_index("ix_job_scores_profile_id", table_name="job_scores")
    op.drop_index("ix_job_scores_job_id", table_name="job_scores")
    op.drop_table("job_scores")
    with op.batch_alter_table("candidate_profiles") as batch:
        batch.drop_constraint("uq_candidate_profiles_name_version", type_="unique")
        batch.drop_column("schema_version")
