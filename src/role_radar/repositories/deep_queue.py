"""Durable logical deep-evaluation queue."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import DeepEvaluationQueueItem


class DeepQueueRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list_for_run(self, run_id: str) -> list[DeepEvaluationQueueItem]:
        return list(
            self._session.scalars(
                select(DeepEvaluationQueueItem)
                .where(DeepEvaluationQueueItem.run_id == run_id)
                .order_by(DeepEvaluationQueueItem.rank)
            )
        )

    def get(self, *, run_id: str, job_id: str) -> DeepEvaluationQueueItem | None:
        return self._session.scalar(
            select(DeepEvaluationQueueItem).where(
                DeepEvaluationQueueItem.run_id == run_id, DeepEvaluationQueueItem.job_id == job_id
            )
        )

    def add(self, **values: object) -> DeepEvaluationQueueItem:
        item = DeepEvaluationQueueItem(**values)
        self._session.add(item)
        self._session.flush()
        return item
