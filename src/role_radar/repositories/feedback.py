"""SQL-only persistence gateway for current product feedback decisions."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from role_radar.db.models import FeedbackDecision


class FeedbackConflictError(ValueError):
    """Stable error when a decision write loses an optimistic revision race."""

    def __init__(self, code: str = "feedback_decision_conflict") -> None:
        self.code = code
        super().__init__(code)


class FeedbackRepository:
    """Append-only revision store; flushes without committing."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def latest_revision(self, run_id: str, job_id: str) -> int:
        value = self._session.scalar(
            select(func.max(FeedbackDecision.revision)).where(
                FeedbackDecision.run_id == run_id,
                FeedbackDecision.job_id == job_id,
            )
        )
        return int(value) if value is not None else 0

    def latest_for_run(self, run_id: str) -> dict[str, FeedbackDecision]:
        rows = self._session.scalars(
            select(FeedbackDecision)
            .where(FeedbackDecision.run_id == run_id)
            .order_by(FeedbackDecision.job_id, FeedbackDecision.revision)
        )
        latest: dict[str, FeedbackDecision] = {}
        for row in rows:
            latest[row.job_id] = row
        return latest

    def history(self, run_id: str, job_id: str) -> list[FeedbackDecision]:
        return list(
            self._session.scalars(
                select(FeedbackDecision)
                .where(
                    FeedbackDecision.run_id == run_id,
                    FeedbackDecision.job_id == job_id,
                )
                .order_by(FeedbackDecision.revision)
            )
        )

    def submit(
        self,
        *,
        run_id: str,
        job_id: str,
        label: str,
        primary_reason: str,
        secondary_reasons: tuple[str, ...] = (),
        note: str | None = None,
        relevance_band: str | None = None,
        policy_version: str | None = None,
        profile_id: str | None = None,
        row_version: int | None = None,
        schema_version: int | None = None,
        canonical_profile_sha256: str | None = None,
        policy_hash: str | None = None,
        relevance_version: str | None = None,
        text_sha256: str | None = None,
        reviewer: str | None = None,
        expected_revision: int | None = None,
    ) -> tuple[FeedbackDecision, bool]:
        """Append one revision; identical content replays the latest row.

        Returns (row, created).  Raises FeedbackConflictError when
        expected_revision does not match the stored latest revision.
        """

        current = self.latest_revision(run_id, job_id)
        if expected_revision is not None and expected_revision != current:
            raise FeedbackConflictError()
        secondary = tuple(secondary_reasons)
        if current > 0:
            latest = self.history(run_id, job_id)[-1]
            if (
                latest.label == label
                and latest.primary_reason == primary_reason
                and tuple(latest.secondary_reasons_json or ()) == secondary
                and (latest.note or None) == (note or None)
                and (latest.relevance_band or None) == (relevance_band or None)
                and (latest.policy_version or None) == (policy_version or None)
                and (latest.profile_id or None) == (profile_id or None)
                and (latest.row_version or None) == (row_version or None)
                and (latest.schema_version or None) == (schema_version or None)
                and (latest.canonical_profile_sha256 or None)
                == (canonical_profile_sha256 or None)
                and (latest.policy_hash or None) == (policy_hash or None)
                and (latest.relevance_version or None) == (relevance_version or None)
                and (latest.text_sha256 or None) == (text_sha256 or None)
                and (latest.reviewer or None) == (reviewer or None)
            ):
                return latest, False
        row = FeedbackDecision(
            run_id=run_id,
            job_id=job_id,
            revision=current + 1,
            label=label,
            primary_reason=primary_reason,
            secondary_reasons_json=list(secondary),
            note=note,
            relevance_band=relevance_band,
            policy_version=policy_version,
            profile_id=profile_id,
            row_version=row_version,
            schema_version=schema_version,
            canonical_profile_sha256=canonical_profile_sha256,
            policy_hash=policy_hash,
            relevance_version=relevance_version,
            text_sha256=text_sha256,
            reviewer=reviewer,
            decided_at=datetime.now(UTC),
        )
        self._session.add(row)
        self._session.flush()
        return row, True

    def summary(self, run_id: str) -> dict[str, Any]:
        latest = self.latest_for_run(run_id)
        counts = {"apply": 0, "maybe": 0, "reject": 0}
        primary_counts: dict[str, int] = {}
        secondary_counts: dict[str, int] = {}
        for row in latest.values():
            if row.label in counts:
                counts[row.label] += 1
            primary_counts[row.primary_reason] = primary_counts.get(row.primary_reason, 0) + 1
            for reason in row.secondary_reasons_json or ():
                secondary_counts[reason] = secondary_counts.get(reason, 0) + 1
        return {
            "run_id": run_id,
            "decided_jobs": len(latest),
            "labels": counts,
            "primary_reason_counts": dict(sorted(primary_counts.items())),
            "secondary_reason_counts": dict(sorted(secondary_counts.items())),
        }
