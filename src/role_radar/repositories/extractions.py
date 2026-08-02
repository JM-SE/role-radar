"""Persistencia de operaciones de extracción; sin policy ni correctivos."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import JobExtraction
from role_radar.domain.enums import ExtractionStatus


class ExtractionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(
        self,
        *,
        job_id: str,
        schema_version: str,
        prompt_version: str,
        model_capability: str,
        input_hash: str,
        status: ExtractionStatus = ExtractionStatus.PENDING,
    ) -> JobExtraction:
        extraction = JobExtraction(
            job_id=job_id,
            schema_version=schema_version,
            prompt_version=prompt_version,
            model_capability=model_capability,
            input_hash=input_hash,
            validation_status=status,
        )
        self._session.add(extraction)
        self._session.flush()
        return extraction

    def get(self, extraction_id: str) -> JobExtraction | None:
        return self._session.get(JobExtraction, extraction_id)

    def get_latest(self, job_id: str) -> JobExtraction | None:
        stmt = (
            select(JobExtraction)
            .where(JobExtraction.job_id == job_id)
            .order_by(JobExtraction.updated_at.desc(), JobExtraction.created_at.desc())
        )
        return self._session.scalars(stmt).first()

    def find_operation(
        self,
        *,
        job_id: str,
        input_hash: str,
        schema_version: str,
        prompt_version: str,
    ) -> JobExtraction | None:
        stmt = select(JobExtraction).where(
            JobExtraction.job_id == job_id,
            JobExtraction.input_hash == input_hash,
            JobExtraction.schema_version == schema_version,
            JobExtraction.prompt_version == prompt_version,
        )
        return self._session.scalars(stmt).first()

    def increment_attempt(self, extraction_id: str) -> JobExtraction | None:
        extraction = self.get(extraction_id)
        if extraction is None:
            return None
        extraction.attempt_count += 1
        extraction.active_corrective_attempt = 1 if extraction.attempt_count > 1 else 0
        extraction.validation_status = ExtractionStatus.PROCESSING
        extraction.processing_started_at = datetime.now(UTC)
        extraction.updated_at = datetime.now(UTC)
        self._session.flush()
        return extraction

    def update_result(
        self,
        extraction_id: str,
        *,
        payload: dict[str, Any],
        status: ExtractionStatus = ExtractionStatus.VALID,
        broker_task_id: str | None = None,
        model_identifier: str | None = None,
        finish_reason: str | None = None,
        usage_json: dict[str, int] | None = None,
    ) -> JobExtraction:
        extraction = self._required(extraction_id)
        extraction.extraction_json = payload
        extraction.validation_status = status
        extraction.broker_task_id = broker_task_id
        extraction.model_identifier = model_identifier
        extraction.finish_reason = finish_reason
        extraction.usage_json = usage_json
        extraction.error_class = None
        extraction.error_code = None
        extraction.active_corrective_attempt = 0
        extraction.processing_started_at = None
        extraction.updated_at = datetime.now(UTC)
        self._session.flush()
        return extraction

    def update_failure(
        self,
        extraction_id: str,
        *,
        status: ExtractionStatus,
        error_class: str,
        error_code: str,
        broker_task_id: str | None = None,
        model_identifier: str | None = None,
        finish_reason: str | None = None,
        usage_json: dict[str, int] | None = None,
    ) -> JobExtraction:
        extraction = self._required(extraction_id)
        extraction.extraction_json = None
        extraction.validation_status = status
        extraction.error_class = error_class[:64]
        extraction.error_code = error_code[:128]
        extraction.broker_task_id = broker_task_id
        extraction.model_identifier = model_identifier
        extraction.finish_reason = finish_reason
        extraction.usage_json = usage_json
        extraction.processing_started_at = None
        extraction.updated_at = datetime.now(UTC)
        self._session.flush()
        return extraction

    def _required(self, extraction_id: str) -> JobExtraction:
        extraction = self.get(extraction_id)
        if extraction is None:
            raise ValueError("extraction not found")
        return extraction
