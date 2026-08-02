"""phase06 deep evaluation — durable selection and Thinking results."""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "577682b6d35a"
down_revision: str | None = "9c6e1f4a2b70"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "job_deep_evaluations",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("profile_id", sa.String(36), nullable=False),
        sa.Column("extraction_id", sa.String(36), nullable=False),
        sa.Column("job_score_id", sa.String(36), nullable=False),
        sa.Column("operation_key", sa.String(512), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("prompt_version", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(64), nullable=False),
        sa.Column("selector_policy_version", sa.String(64), nullable=False),
        sa.Column("selector_policy_hash", sa.String(64), nullable=False),
        sa.Column("model_capability", sa.String(64), nullable=False),
        sa.Column("model_identifier", sa.String(255), nullable=True),
        sa.Column("broker_task_id", sa.String(128), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_corrective_attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("request_fingerprint", sa.String(64), nullable=True),
        sa.Column("processing_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fit_score", sa.Integer(), nullable=True),
        sa.Column("decision", sa.String(32), nullable=True),
        sa.Column("strengths_json", sa.JSON(), nullable=True),
        sa.Column("gaps_json", sa.JSON(), nullable=True),
        sa.Column("model_concerns_json", sa.JSON(), nullable=True),
        sa.Column("uncertainties_json", sa.JSON(), nullable=True),
        sa.Column("recommended_action", sa.String(16), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("adjustment", sa.Integer(), nullable=True),
        sa.Column("final_score", sa.Integer(), nullable=True),
        sa.Column("finish_reason", sa.String(32), nullable=True),
        sa.Column("usage_json", sa.JSON(), nullable=True),
        sa.Column("error_class", sa.String(64), nullable=True),
        sa.Column("error_code", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["profile_id"], ["candidate_profiles.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["extraction_id"], ["job_extractions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_score_id"], ["job_scores.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("operation_key", name="uq_job_deep_evaluations_operation_key"),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 2", name="ck_deep_attempt_count"
        ),
        sa.CheckConstraint(
            "active_corrective_attempt IN (0, 1)", name="ck_deep_corrective_attempt"
        ),
        sa.CheckConstraint(
            "fit_score IS NULL OR (fit_score >= 0 AND fit_score <= 100)", name="ck_deep_fit_score"
        ),
        sa.CheckConstraint(
            "final_score IS NULL OR (final_score >= 0 AND final_score <= 100)",
            name="ck_deep_final_score",
        ),
    )
    for name, columns in (
        ("ix_deep_eval_job", ["job_id"]),
        ("ix_deep_eval_profile", ["profile_id"]),
        ("ix_deep_eval_extraction", ["extraction_id"]),
        ("ix_deep_eval_score", ["job_score_id"]),
        ("ix_deep_eval_input", ["input_hash"]),
        ("ix_deep_eval_task", ["broker_task_id"]),
        ("ix_deep_eval_fingerprint", ["request_fingerprint"]),
    ):
        op.create_index(name, "job_deep_evaluations", columns)
    op.create_table(
        "deep_evaluation_queue",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("job_score_id", sa.String(36), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("selection_reason", sa.String(32), nullable=False),
        sa.Column("selector_policy_version", sa.String(64), nullable=False),
        sa.Column("selector_policy_hash", sa.String(64), nullable=False),
        sa.Column("ambiguity_resolution_version", sa.String(64), nullable=False),
        sa.Column("selection_input_hash", sa.String(64), nullable=False),
        sa.Column("resolvable_ambiguity_codes_json", sa.JSON(), nullable=False),
        sa.Column("evaluation_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["job_search_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_score_id"], ["job_scores.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evaluation_id"], ["job_deep_evaluations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "job_id", name="uq_deep_queue_run_job"),
        sa.UniqueConstraint("run_id", "rank", name="uq_deep_queue_run_rank"),
        sa.UniqueConstraint("run_id", "job_score_id", name="uq_deep_queue_run_score"),
        sa.CheckConstraint("rank >= 1 AND rank <= 10", name="ck_deep_queue_rank"),
    )
    op.create_index("ix_deep_queue_run", "deep_evaluation_queue", ["run_id"])
    op.create_index("ix_deep_queue_job", "deep_evaluation_queue", ["job_id"])
    op.create_index("ix_deep_queue_score", "deep_evaluation_queue", ["job_score_id"])
    op.create_index(
        "ix_deep_queue_selection_input", "deep_evaluation_queue", ["selection_input_hash"]
    )
    op.create_index("ix_deep_queue_evaluation", "deep_evaluation_queue", ["evaluation_id"])


def downgrade() -> None:
    for name in (
        "ix_deep_queue_evaluation",
        "ix_deep_queue_selection_input",
        "ix_deep_queue_score",
        "ix_deep_queue_job",
        "ix_deep_queue_run",
    ):
        op.drop_index(name, table_name="deep_evaluation_queue")
    op.drop_table("deep_evaluation_queue")
    for name in (
        "ix_deep_eval_fingerprint",
        "ix_deep_eval_task",
        "ix_deep_eval_input",
        "ix_deep_eval_score",
        "ix_deep_eval_extraction",
        "ix_deep_eval_profile",
        "ix_deep_eval_job",
    ):
        op.drop_index(name, table_name="job_deep_evaluations")
    op.drop_table("job_deep_evaluations")
