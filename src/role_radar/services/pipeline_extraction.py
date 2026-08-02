"""Extracción persistente con una frontera estricta prepare/execute/finalize."""

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from pydantic import ValidationError
from sqlalchemy.orm import Session

from role_radar.broker.protocols import (
    LLMProvider,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)
from role_radar.db.models import Job, JobExtraction
from role_radar.domain.enums import ExtractionStatus
from role_radar.extraction.prompts import (
    PROMPT_VERSION,
    build_corrective_messages,
    build_extraction_messages,
)
from role_radar.extraction.schema import SCHEMA_VERSION, get_extraction_schema
from role_radar.extraction.schemas import JobExtractionPayload
from role_radar.extraction.validator import validate_extraction
from role_radar.normalization.text import description_hash, normalize_whitespace
from role_radar.repositories.extractions import ExtractionRepository

CAPABILITY = "structured-extraction"


@dataclass(frozen=True)
class PreparedExtraction:
    extraction_id: str
    job_id: str
    input_hash: str
    attempt: int
    fingerprint: str
    request: StructuredGenerationRequest


@dataclass(frozen=True)
class ExtractionExecution:
    prepared: PreparedExtraction
    result: StructuredGenerationResult | None = None
    error: ProviderError | None = None


@dataclass(frozen=True)
class FinalizedExtraction:
    extraction_id: str
    status: ExtractionStatus
    retry_corrective: bool = False


class PipelineExtractionService:
    """Todas las coroutines reciben y devuelven valores sin identidad ORM."""

    def __init__(self, session_factory: Any, *, provider: LLMProvider) -> None:
        self._session_factory = session_factory
        self._provider = provider

    def prepare(self, job_id: str, *, corrective: bool = False) -> PreparedExtraction | None:
        with self._session_factory() as session:
            job = session.get(Job, job_id)
            if job is None:
                raise LookupError("job not found")
            description = job.description
            if description is None or not description.strip():
                raise ValueError("job description is empty")
            description = normalize_whitespace(description)
            input_hash = job.description_hash or description_hash(description)
            if input_hash is None:
                raise ValueError("job description hash is unavailable")
            if job.description_hash is None:
                job.description_hash = input_hash
            operations = ExtractionRepository(session)
            extraction = operations.find_operation(
                job_id=job_id,
                input_hash=input_hash,
                schema_version=SCHEMA_VERSION,
                prompt_version=PROMPT_VERSION,
            )
            if extraction is None:
                extraction = operations.add(
                    job_id=job_id,
                    input_hash=input_hash,
                    schema_version=SCHEMA_VERSION,
                    prompt_version=PROMPT_VERSION,
                    model_capability=CAPABILITY,
                )
            if extraction.validation_status in {
                ExtractionStatus.VALID,
                ExtractionStatus.NEEDS_REVIEW,
                ExtractionStatus.FAILED,
            }:
                session.commit()
                return None
            if (
                extraction.attempt_count >= 2
                and extraction.validation_status != ExtractionStatus.PROCESSING
            ):
                operations.update_failure(
                    extraction.id,
                    status=ExtractionStatus.NEEDS_REVIEW,
                    error_class="indeterminate",
                    error_code="attempt_budget_exhausted",
                )
                session.commit()
                return None

            attempt = extraction.attempt_count
            rebuilding_active_attempt = extraction.validation_status == ExtractionStatus.PROCESSING
            active_corrective = extraction.active_corrective_attempt
            if rebuilding_active_attempt:
                # Recovery/replay rebuilds the exact request; it never consumes a budget.
                attempt = max(1, extraction.attempt_count)
                active_corrective = extraction.active_corrective_attempt
            else:
                attempt += 1
                active_corrective = 1 if corrective or attempt == 2 else 0
                extraction.attempt_count = attempt
                extraction.active_corrective_attempt = active_corrective
                extraction.validation_status = ExtractionStatus.PROCESSING
                extraction.processing_started_at = datetime.now(UTC)

            schema = get_extraction_schema()
            messages = (
                build_corrective_messages(
                    title=job.title,
                    company=job.company,
                    location=job.location,
                    description=description,
                    response_schema=schema,
                    errors=("previous_attempt_invalid",),
                )
                if active_corrective
                else build_extraction_messages(
                    title=job.title,
                    company=job.company,
                    location=job.location,
                    description=description,
                    response_schema=schema,
                )
            )
            request = StructuredGenerationRequest(
                operation_id=job.id,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
                schema_version=SCHEMA_VERSION,
                corrective_attempt=cast(Literal[0, 1], active_corrective),
                messages=tuple(messages),
                response_schema=schema,
                capability=CAPABILITY,
                trace={
                    "job_id": job.id,
                    "extraction_id": extraction.id,
                    "prompt_version": PROMPT_VERSION,
                    "schema_version": SCHEMA_VERSION,
                },
            )
            fingerprint = _fingerprint(request)
            if (
                rebuilding_active_attempt
                and extraction.request_fingerprint is not None
                and extraction.request_fingerprint != fingerprint
            ):
                raise RuntimeError("request_reconstruction_mismatch")
            extraction.request_fingerprint = fingerprint
            session.commit()
            return PreparedExtraction(
                extraction_id=extraction.id,
                job_id=job.id,
                input_hash=input_hash,
                attempt=attempt,
                fingerprint=fingerprint,
                request=request,
            )

    async def execute(self, prepared: PreparedExtraction) -> ExtractionExecution:
        try:
            result = await self._provider.generate_structured(prepared.request)
            return ExtractionExecution(prepared, result=result)
        except ProviderError as exc:
            return ExtractionExecution(prepared, error=exc)

    def finalize(self, execution: ExtractionExecution) -> FinalizedExtraction:
        prepared = execution.prepared
        with self._session_factory() as session:
            extraction = session.get(JobExtraction, prepared.extraction_id)
            if extraction is None:
                raise LookupError("extraction not found")
            if (
                extraction.attempt_count != prepared.attempt
                or extraction.request_fingerprint != prepared.fingerprint
            ):
                raise RuntimeError("request_reconstruction_mismatch")
            repository = ExtractionRepository(session)
            if execution.error is not None:
                repository.update_failure(
                    extraction.id,
                    status=(
                        ExtractionStatus.PROCESSING
                        if execution.error.retryable
                        else ExtractionStatus.FAILED
                    ),
                    error_class=_safe(execution.error.error_class),
                    error_code=_safe(execution.error.code),
                    broker_task_id=execution.error.provider_task_id,
                )
                session.commit()
                return FinalizedExtraction(extraction.id, extraction.validation_status)
            assert execution.result is not None
            payload, errors = _parse_result(execution.result, prepared.job_id, session)
            if payload is not None and not errors:
                repository.update_result(
                    extraction.id,
                    payload=payload.model_dump(mode="json"),
                    broker_task_id=execution.result.provider_task_id,
                    model_identifier=execution.result.model_identifier,
                    finish_reason=execution.result.finish_reason,
                    usage_json=execution.result.usage,
                )
                session.commit()
                return FinalizedExtraction(extraction.id, ExtractionStatus.VALID)
            if prepared.attempt < 2:
                extraction.validation_status = ExtractionStatus.PENDING
                extraction.active_corrective_attempt = 0
                extraction.error_class = "validation"
                extraction.error_code = "provider_output_invalid"
                extraction.processing_started_at = None
                extraction.updated_at = datetime.now(UTC)
                session.commit()
                return FinalizedExtraction(
                    extraction.id, ExtractionStatus.PENDING, retry_corrective=True
                )
            repository.update_failure(
                extraction.id,
                status=ExtractionStatus.NEEDS_REVIEW,
                error_class="validation",
                error_code="corrective_invalid",
                broker_task_id=execution.result.provider_task_id,
                model_identifier=execution.result.model_identifier,
                finish_reason=execution.result.finish_reason,
                usage_json=execution.result.usage,
            )
            session.commit()
            return FinalizedExtraction(extraction.id, ExtractionStatus.NEEDS_REVIEW)


def _parse_result(
    result: StructuredGenerationResult, job_id: str, session: Session
) -> tuple[JobExtractionPayload | None, tuple[str, ...]]:
    try:
        decoded = json.loads(result.content)
        payload = JobExtractionPayload.model_validate(decoded)
    except (json.JSONDecodeError, TypeError, ValidationError):
        return None, ("payload_invalid",)
    job = session.get(Job, job_id)
    if job is None or not job.description:
        return None, ("job_description_missing",)
    return payload, validate_extraction(payload, normalize_whitespace(job.description))


def _fingerprint(request: StructuredGenerationRequest) -> str:
    encoded = json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _safe(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._:-" else "_" for char in value)[:128]
