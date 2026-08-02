"""Decisiones puras y recomputación idempotente de stats."""

from collections.abc import Iterable
from typing import Any

from role_radar.db.models import RunJob
from role_radar.domain.enums import RunJobStage, RunJobStatus

STAT_KEYS = (
    "sources_ok",
    "sources_failed",
    "collected",
    "new_jobs",
    "duplicates",
    "prefiltered",
    "extracted",
    "extraction_failed",
    "scored",
    "score_failed",
    "deep_selected",
    "deep_evaluated",
    "deep_failed",
    "deep_needs_review",
    "deep_skipped",
    "failed",
    "digests_sent",
    "digests_failed",
    "digests_unknown",
    "notified_jobs",
    "notification_failed",
    "notification_unknown",
    "notification_skipped",
)


def checkpoint_succeeded(row: RunJob | None) -> bool:
    return row is not None and row.status == RunJobStatus.SUCCEEDED


def recompute_stats(
    source_results: dict[str, Any] | None, run_jobs: Iterable[RunJob]
) -> dict[str, int]:
    stats = {key: 0 for key in STAT_KEYS}
    for result in (source_results or {}).values():
        if result.get("status") == "ok":
            stats["sources_ok"] += 1
            stats["collected"] += int(result.get("collected", 0))
            stats["new_jobs"] += int(result.get("new_jobs", 0))
            stats["duplicates"] += int(result.get("duplicates", 0))
            stats["prefiltered"] += int(result.get("prefiltered", 0))
            stats["failed"] += int(result.get("failed", 0))
        else:
            stats["sources_failed"] += 1
    for row in run_jobs:
        if row.stage is RunJobStage.EXTRACTED:
            if row.status is RunJobStatus.SUCCEEDED:
                stats["extracted"] += 1
            elif row.status is RunJobStatus.FAILED:
                stats["extraction_failed"] += 1
        if row.stage is RunJobStage.SCORED:
            if row.status is RunJobStatus.SUCCEEDED:
                stats["scored"] += 1
            elif row.status is RunJobStatus.FAILED:
                stats["score_failed"] += 1
        if row.stage is RunJobStage.DEEP_EVALUATED:
            if row.status in {RunJobStatus.PENDING, RunJobStatus.IN_PROGRESS}:
                stats["deep_selected"] += 1
            elif row.status is RunJobStatus.SUCCEEDED:
                stats["deep_selected"] += 1
                stats["deep_evaluated"] += 1
            elif row.status is RunJobStatus.FAILED:
                stats["deep_selected"] += 1
                if row.error_code == "needs_review":
                    stats["deep_needs_review"] += 1
                else:
                    stats["deep_failed"] += 1
            elif row.status is RunJobStatus.SKIPPED:
                stats["deep_skipped"] += 1
    return stats
