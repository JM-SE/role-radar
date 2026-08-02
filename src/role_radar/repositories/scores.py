"""Persistence gateway for immutable, idempotent JobScore rows."""

from __future__ import annotations

from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from role_radar.db.models import JobScore
from role_radar.matching.contracts import MatchResult


class ScoreRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_operation(self, operation_key: str) -> JobScore | None:
        return self._session.scalar(select(JobScore).where(JobScore.operation_key == operation_key))

    def get_or_create_operation(
        self, result: MatchResult, *, job_id: str, profile_id: str
    ) -> JobScore:
        existing = self.get_by_operation(result.operation_key)
        if existing is not None:
            return existing
        row = JobScore(
            job_id=job_id,
            profile_id=profile_id,
            extraction_id=result.extraction_id,
            operation_key=result.operation_key,
            scoring_version=result.scoring_version,
            policy_version=result.policy_version,
            input_hash=result.input_hash,
            preliminary_score=result.preliminary_score,
            eligible=result.eligible,
            signal_json=[asdict(signal) for signal in result.signals],
            hard_blocker_json=[asdict(blocker) for blocker in result.blockers],
            ambiguity_json=[asdict(ambiguity) for ambiguity in result.ambiguities],
        )
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
        except IntegrityError:
            found = self.get_by_operation(result.operation_key)
            if found is None:
                raise
            return found
        return row

    def latest(self, *, job_id: str, profile_id: str) -> JobScore | None:
        return self._session.scalar(
            select(JobScore)
            .where(JobScore.job_id == job_id, JobScore.profile_id == profile_id)
            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
        )

    def latest_for_jobs(self, *, job_ids: list[str], profile_id: str) -> dict[str, JobScore]:
        if not job_ids:
            return {}
        rows = self._session.scalars(
            select(JobScore)
            .where(JobScore.job_id.in_(job_ids), JobScore.profile_id == profile_id)
            .order_by(JobScore.created_at.desc(), JobScore.id.asc())
        )
        found: dict[str, JobScore] = {}
        for row in rows:
            found.setdefault(row.job_id, row)
        return found


# Name used in the phase specification; retain the concise singular alias too.
ScoresRepository = ScoreRepository
