"""Versioned protocol constants for the F10.1 freeze."""

PROTOCOL_VERSION = "f10.1-controlled-acquisition-v1"
PLAN_VERSION = "f10.1-plan-v1"
SELECTION_VERSION = "f10.1-selection-v1"
IDENTITY_VERSION = "f10.1-identity-v1"
SNAPSHOT_VERSION = "f10.1-snapshot-v1"
JOURNAL_VERSION = "f10.1-journal-v1"

TARGETS: dict[str, int] = {"jobicy": 20, "greenhouse": 15, "lever": 15}
ALLOWED_FAMILIES = frozenset(TARGETS)
MAX_WIRE_ATTEMPTS = 100
FUTURE_TOLERANCE_SECONDS = 5 * 60
LOOKBACK_DAYS = 14
DEFAULT_SNAPSHOT_ROOT = "/opt/role-radar/data/evaluation/f10.1"

EXTERNAL_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_version",
        "result",
        "dataset_id",
        "count",
        "semantic_dataset_sha256",
        "snapshot_sha256",
        "profile_id",
        "profile_version",
        "profile_schema_version",
        "profile_sha256",
        "source_commit",
        "source_diff_sha256",
        "source_status_sha256",
        "alembic_head",
        "selection_as_of_utc",
        "cutoff_utc",
        "lookback_days",
        "target_counts",
        "actual_counts",
        "deficit_counts",
        "fallback_count",
        "request_counts",
        "rejection_counts",
        "cleanup_result",
        "verification_result",
    }
)
