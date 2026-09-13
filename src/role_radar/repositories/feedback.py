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
            decided_at=datetime.now(UTC),
        )
        self._session.add(row)
        self._session.flush()
        return row, True

    def summary(self, run_id: str) -> dict[str, Any]:
        latest = self.latest_for_run(run_id)
        counts = {"apply": 0, "maybe": 0, "reject": 0}
        for row in latest.values():
            if row.label in counts:
                counts[row.label] += 1
        return {
            "run_id": run_id,
            "decided_jobs": len(latest),
            "labels": counts,
        }
