"""Write-once/idempotent gateway for deep evaluation rows."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import JobDeepEvaluation
from role_radar.domain.enums import DeepEvaluationStatus


class DeepEvaluationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, evaluation_id: str) -> JobDeepEvaluation | None:
        return self._session.get(JobDeepEvaluation, evaluation_id)

    def get_by_operation(self, operation_key: str) -> JobDeepEvaluation | None:
        return self._session.scalar(
            select(JobDeepEvaluation).where(JobDeepEvaluation.operation_key == operation_key)
        )

    def create(self, **values: object) -> JobDeepEvaluation:
        row = JobDeepEvaluation(**values)
        self._session.add(row)
        self._session.flush()
        return row

    def terminal(self, row: JobDeepEvaluation) -> bool:
        return row.status in {
            DeepEvaluationStatus.VALID,
            DeepEvaluationStatus.NEEDS_REVIEW,
            DeepEvaluationStatus.FAILED,
        }

    def set_processing(
        self, row: JobDeepEvaluation, *, attempt: int, corrective: int, fingerprint: str
    ) -> None:
        if self.terminal(row):
            return
        row.status = DeepEvaluationStatus.PROCESSING
        row.attempt_count = attempt
        row.active_corrective_attempt = corrective
        row.request_fingerprint = fingerprint
        from datetime import UTC, datetime

        row.processing_started_at = datetime.now(UTC)
        self._session.flush()

    def finish_invalid(self, row: JobDeepEvaluation, *, corrective: bool, error_code: str) -> None:
        if self.terminal(row):
            return
        from datetime import UTC, datetime

        row.error_class = "validation"
        row.error_code = error_code[:128]
        row.updated_at = datetime.now(UTC)
        if corrective:
            row.status = DeepEvaluationStatus.NEEDS_REVIEW
        else:
            row.status = DeepEvaluationStatus.PENDING
            row.active_corrective_attempt = 0
        self._session.flush()

    def finish_failure(
        self,
        row: JobDeepEvaluation,
        *,
        error_class: str,
        error_code: str,
        task_id: str | None = None,
    ) -> None:
        if self.terminal(row):
            return
        row.status = DeepEvaluationStatus.FAILED
        row.error_class = error_class[:64]
        row.error_code = error_code[:128]
        row.broker_task_id = task_id
        self._session.flush()

    def finish_valid(
        self,
        row: JobDeepEvaluation,
        *,
        payload: dict[str, Any],
        adjustment: int,
        final_score: int,
        task_id: str | None,
        model_identifier: str | None,
        finish_reason: str,
        usage: dict[str, int],
    ) -> None:
        if self.terminal(row):
            return
        row.status = DeepEvaluationStatus.VALID
        row.fit_score = payload["fit_score"]
        row.decision = payload["decision"]
        for name in ("strengths", "gaps", "model_concerns", "uncertainties"):
            setattr(row, f"{name}_json", payload[name])
        row.recommended_action = payload["recommended_action"]
        row.confidence = payload["confidence"]
        row.adjustment = adjustment
        row.final_score = final_score
        row.broker_task_id = task_id
        row.model_identifier = model_identifier
        row.finish_reason = finish_reason
        row.usage_json = usage
        self._session.flush()
