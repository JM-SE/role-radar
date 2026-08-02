"""Orquestación de extracción: provider + validación + persistencia."""

import json
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy.orm import Session

from role_radar.broker.protocols import (
    LLMProvider,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)
from role_radar.db.models import Job, JobExtraction
from role_radar.domain.enums import ExtractionStatus, RunJobStage, RunJobStatus
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
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository

CAPABILITY = "structured-extraction"


class ExtractionService:
    """Coordina una operación durable y nunca hace commit propio."""

    def __init__(
        self,
        session: Session,
        *,
        provider: LLMProvider,
        jobs: JobRepository | None = None,
        extractions: ExtractionRepository | None = None,
        runs: RunRepository | None = None,
    ) -> None:
        self._provider = provider
        self._jobs = jobs or JobRepository(session)
        self._extractions = extractions or ExtractionRepository(session)
        self._runs = runs or RunRepository(session)

    async def extract_job(self, *, job_id: str, run_id: str | None = None) -> JobExtraction:
        job = self._jobs.get(job_id)
        if job is None:
            raise ValueError("job not found")
        description = job.description
        if description is None or not description.strip():
            raise ValueError("job description is empty")
        description = normalize_whitespace(description)
        input_hash = job.description_hash or description_hash(description)
        if input_hash is None:
            raise ValueError("job description hash is unavailable")
        if job.description_hash is None:
            job.description_hash = input_hash

        extraction = self._extractions.find_operation(
            job_id=job.id,
            input_hash=input_hash,
            schema_version=SCHEMA_VERSION,
            prompt_version=PROMPT_VERSION,
        )
        if extraction is None:
            extraction = self._extractions.add(
                job_id=job.id,
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
            self._record_run(run_id, job.id, extraction.validation_status)
            return extraction
        if extraction.attempt_count >= 2:
            extraction = self._extractions.update_failure(
                extraction.id,
                status=ExtractionStatus.NEEDS_REVIEW,
                error_class="indeterminate",
                error_code="attempt_budget_exhausted",
            )
            self._record_run(run_id, job.id, extraction.validation_status)
            return extraction

        schema = get_extraction_schema()
        corrective_attempt: Literal[0, 1] = 1 if extraction.attempt_count == 1 else 0
        messages = build_extraction_messages(
            title=job.title,
            company=job.company,
            location=job.location,
            description=description,
            response_schema=schema,
        )
        if corrective_attempt:
            messages = build_corrective_messages(
                title=job.title,
                company=job.company,
                location=job.location,
                description=description,
                response_schema=schema,
                errors=("previous_attempt_invalid",),
            )
        result, provider_error = await self._call_provider(
            extraction,
            StructuredGenerationRequest(
                operation_id=job.id,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
                schema_version=SCHEMA_VERSION,
                corrective_attempt=corrective_attempt,
                messages=messages,
                response_schema=schema,
                capability=CAPABILITY,
                trace={
                    "job_id": job.id,
                    "extraction_id": extraction.id,
                    "prompt_version": PROMPT_VERSION,
                    "schema_version": SCHEMA_VERSION,
                },
            ),
        )
        if provider_error is not None:
            if provider_error.kind == "output_invalid" and corrective_attempt == 0:
                return await self._corrective(
                    job=job,
                    description=description,
                    extraction=extraction,
                    schema=schema,
                    previous_output=None,
                    errors=("provider_output_invalid",),
                    run_id=run_id,
                )
            status = self._status_for_provider_error(provider_error)
            extraction = self._extractions.update_failure(
                extraction.id,
                status=status,
                error_class=self._safe_code(provider_error.error_class),
                error_code=self._safe_code(provider_error.code),
                broker_task_id=provider_error.provider_task_id,
            )
            self._record_run(run_id, job.id, status)
            return extraction

        assert result is not None
        payload, errors = self._parse_result(result, description)
        if payload is not None and not errors:
            extraction = self._extractions.update_result(
                extraction.id,
                payload=payload.model_dump(mode="json"),
                broker_task_id=result.provider_task_id,
                model_identifier=result.model_identifier,
                finish_reason=result.finish_reason,
                usage_json=result.usage,
            )
            self._record_run(run_id, job.id, ExtractionStatus.VALID)
            return extraction
        return await self._corrective(
            job=job,
            description=description,
            extraction=extraction,
            schema=schema,
            previous_output=result.content,
            errors=errors or ("payload_invalid",),
            run_id=run_id,
            first_result=result,
        )

    async def extract_pending(self, *, limit: int) -> list[JobExtraction]:
        if limit < 1:
            raise ValueError("limit must be positive")
        results: list[JobExtraction] = []
        offset = 0
        page_size = max(limit, 50)
        while len(results) < limit:
            jobs = self._jobs.list_with_description(limit=page_size, offset=offset)
            if not jobs:
                break
            offset += len(jobs)
            for job in jobs:
                if len(results) >= limit:
                    break
                input_hash = job.description_hash or description_hash(job.description)
                operation = (
                    None
                    if input_hash is None
                    else self._extractions.find_operation(
                        job_id=job.id,
                        input_hash=input_hash,
                        schema_version=SCHEMA_VERSION,
                        prompt_version=PROMPT_VERSION,
                    )
                )
                if operation is not None and operation.validation_status in {
                    ExtractionStatus.VALID,
                    ExtractionStatus.NEEDS_REVIEW,
                    ExtractionStatus.FAILED,
                }:
                    continue
                results.append(await self.extract_job(job_id=job.id))
            if len(jobs) < page_size:
                break
        return results

    async def _call_provider(
        self,
        extraction: JobExtraction,
        request: StructuredGenerationRequest,
    ) -> tuple[StructuredGenerationResult | None, ProviderError | None]:
        self._extractions.increment_attempt(extraction.id)
        try:
            return await self._provider.generate_structured(request), None
        except ProviderError as exc:
            return None, exc

    async def _corrective(
        self,
        *,
        job: Job,
        description: str,
        extraction: JobExtraction,
        schema: dict[str, Any],
        previous_output: str | None,
        errors: tuple[str, ...],
        run_id: str | None,
        first_result: StructuredGenerationResult | None = None,
    ) -> JobExtraction:
        if extraction.attempt_count >= 2:
            updated = self._extractions.update_failure(
                extraction.id,
                status=ExtractionStatus.NEEDS_REVIEW,
                error_class="validation",
                error_code="corrective_attempt_required",
                broker_task_id=first_result.provider_task_id if first_result else None,
            )
            self._record_run(run_id, job.id, updated.validation_status)
            return updated
        messages = build_corrective_messages(
            title=job.title,
            company=job.company,
            location=job.location,
            description=description,
            response_schema=schema,
            errors=errors,
            previous_output=previous_output,
        )
        result, provider_error = await self._call_provider(
            extraction,
            StructuredGenerationRequest(
                operation_id=job.id,
                input_hash=extraction.input_hash,
                prompt_version=PROMPT_VERSION,
                schema_version=SCHEMA_VERSION,
                corrective_attempt=1,
                messages=messages,
                response_schema=schema,
                capability=CAPABILITY,
                trace={
                    "job_id": job.id,
                    "extraction_id": extraction.id,
                    "prompt_version": PROMPT_VERSION,
                    "schema_version": SCHEMA_VERSION,
                },
            ),
        )
        if provider_error is not None:
            updated = self._extractions.update_failure(
                extraction.id,
                status=ExtractionStatus.NEEDS_REVIEW,
                error_class=self._safe_code(provider_error.error_class),
                error_code=self._safe_code(provider_error.code),
                broker_task_id=provider_error.provider_task_id,
            )
            self._record_run(run_id, job.id, updated.validation_status)
            return updated
        assert result is not None
        payload, local_errors = self._parse_result(result, description)
        if payload is not None and not local_errors:
            updated = self._extractions.update_result(
                extraction.id,
                payload=payload.model_dump(mode="json"),
                broker_task_id=result.provider_task_id,
                model_identifier=result.model_identifier,
                finish_reason=result.finish_reason,
                usage_json=result.usage,
            )
            self._record_run(run_id, job.id, ExtractionStatus.VALID)
            return updated
        updated = self._extractions.update_failure(
            extraction.id,
            status=ExtractionStatus.NEEDS_REVIEW,
            error_class="validation",
            error_code="corrective_invalid",
            broker_task_id=result.provider_task_id,
            model_identifier=result.model_identifier,
            finish_reason=result.finish_reason,
            usage_json=result.usage,
        )
        self._record_run(run_id, job.id, updated.validation_status)
        return updated

    @staticmethod
    def _parse_result(
        result: StructuredGenerationResult,
        description: str,
    ) -> tuple[JobExtractionPayload | None, tuple[str, ...]]:
        try:
            decoded = json.loads(result.content)
            payload = JobExtractionPayload.model_validate(decoded)
        except (json.JSONDecodeError, TypeError, ValidationError):
            return None, ("payload_invalid",)
        return payload, validate_extraction(payload, description)

    @staticmethod
    def _status_for_provider_error(error: ProviderError) -> ExtractionStatus:
        if error.kind in {
            "indeterminate",
            "pending_timeout",
            "cancelled",
            "expired",
            "submit_unknown",
        }:
            return ExtractionStatus.NEEDS_REVIEW
        return ExtractionStatus.FAILED

    @staticmethod
    def _safe_code(value: str) -> str:
        return "".join(char if char.isalnum() or char in "._:-" else "_" for char in value)[:128]

    def _record_run(
        self, run_id: str | None, job_id: str, status: ExtractionStatus
    ) -> None:
        if run_id is None:
            return
        run_status = (
            RunJobStatus.SUCCEEDED
            if status == ExtractionStatus.VALID
            else RunJobStatus.FAILED
        )
        self._runs.update_run_job(
            run_id=run_id,
            job_id=job_id,
            stage=RunJobStage.EXTRACTED,
            status=run_status,
            error_message=None if status == ExtractionStatus.VALID else status.value,
        )
