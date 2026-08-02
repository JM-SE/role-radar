"""prepare/execute/finalize orchestration for one deep operation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal, cast

from role_radar.broker.protocols import (
    LLMProvider,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)
from role_radar.config import Settings
from role_radar.db.models import CandidateProfile, Job, JobDeepEvaluation, JobExtraction, JobScore
from role_radar.deep_evaluation.ambiguity_resolution import resolve_ambiguities_v1
from role_radar.deep_evaluation.contracts import DeepEvaluationCandidateV1
from role_radar.deep_evaluation.input_builder import DeepEvaluationInputV1, build_deep_input
from role_radar.deep_evaluation.policy import DeepEvaluationPolicyV1, calculate_adjustment
from role_radar.deep_evaluation.prompts import (
    PROMPT_VERSION,
    build_corrective_messages,
    build_deep_messages,
)
from role_radar.deep_evaluation.schema import SCHEMA_VERSION, get_deep_evaluation_schema
from role_radar.deep_evaluation.validator import validate_result
from role_radar.domain.enums import DeepEvaluationStatus
from role_radar.repositories.deep_evaluations import DeepEvaluationRepository

CAPABILITY = "deep-job-evaluation"


@dataclass(frozen=True, slots=True)
class PreparedDeepEvaluation:
    evaluation_id: str
    operation_key: str
    input_hash: str
    attempt: int
    fingerprint: str
    input: DeepEvaluationInputV1
    request: StructuredGenerationRequest


@dataclass(frozen=True, slots=True)
class DeepEvaluationExecution:
    prepared: PreparedDeepEvaluation
    result: StructuredGenerationResult | None = None
    error: ProviderError | None = None


@dataclass(frozen=True, slots=True)
class FinalizedDeepEvaluation:
    evaluation_id: str
    status: DeepEvaluationStatus
    retry_corrective: bool = False


class DeepEvaluationService:
    def __init__(
        self, session_factory: Any, *, provider: LLMProvider, settings: Settings | None = None
    ) -> None:
        self._session_factory = session_factory
        self._provider = provider
        self._settings = settings or Settings()
        self._policy = DeepEvaluationPolicyV1(
            high_score_min=self._settings.deep_evaluation_high_score_min,
            ambiguous_score_min=self._settings.deep_evaluation_ambiguous_score_min,
            ambiguous_score_max=self._settings.deep_evaluation_ambiguous_score_max,
            max_per_run=self._settings.deep_evaluation_max_per_run,
            adjustment_limit=self._settings.deep_evaluation_adjustment_limit,
            version=self._settings.deep_evaluation_policy_version,
            ambiguity_resolution_version=self._settings.deep_evaluation_ambiguity_resolution_version,
        )

    def prepare(
        self, job_score_id: str, *, corrective: bool = False
    ) -> PreparedDeepEvaluation | None:
        with self._session_factory() as session:
            score = session.get(JobScore, job_score_id)
            if score is None:
                raise LookupError("job score not found")
            job = session.get(Job, score.job_id)
            profile = session.get(CandidateProfile, score.profile_id)
            extraction = (
                session.get(JobExtraction, score.extraction_id) if score.extraction_id else None
            )
            if (
                job is None
                or profile is None
                or extraction is None
                or extraction.validation_status.value != "valid"
                or extraction.id != score.extraction_id
            ):
                raise ValueError("exact_valid_extraction_required")
            candidate = DeepEvaluationCandidateV1(
                job_id=job.id,
                job_score_id=score.id,
                profile_id=profile.id,
                extraction_id=extraction.id,
                title=job.title,
                company=job.company,
                normalized_location=job.normalized_location,
                first_seen_at=job.first_seen_at,
                preliminary_score=score.preliminary_score,
                eligible=score.eligible,
                blockers=tuple(score.hard_blocker_json),
                signals=tuple(score.signal_json),
                ambiguities=tuple(score.ambiguity_json),
                resolvable_ambiguities=resolve_ambiguities_v1(
                    score.ambiguity_json,
                    score.extraction_id,
                    {
                        "id": extraction.id,
                        "validation_status": extraction.validation_status.value,
                        "extraction_json": extraction.extraction_json,
                    },
                ),
                ambiguity_resolution_version=self._policy.ambiguity_resolution_version,
                extraction=extraction.extraction_json,
                profile=profile.profile_json,
            )
            input_value = build_deep_input(
                candidate,
                policy_hash=self._policy.policy_hash,
                policy_version=self._policy.version,
                prompt_version=PROMPT_VERSION,
                schema_version=SCHEMA_VERSION,
            )
            input_hash = input_value.input_hash()
            operation_key = (
                f"{score.id}:{input_hash}:{PROMPT_VERSION}:{SCHEMA_VERSION}:"
                f"{self._policy.policy_hash}"
            )
            repo = DeepEvaluationRepository(session)
            row = repo.get_by_operation(operation_key)
            if row is None:
                row = repo.create(
                    job_id=job.id,
                    profile_id=profile.id,
                    extraction_id=extraction.id,
                    job_score_id=score.id,
                    operation_key=operation_key,
                    input_hash=input_hash,
                    prompt_version=PROMPT_VERSION,
                    schema_version=SCHEMA_VERSION,
                    selector_policy_version=self._policy.version,
                    selector_policy_hash=self._policy.policy_hash,
                    model_capability=CAPABILITY,
                    status=DeepEvaluationStatus.PENDING,
                )
            if repo.terminal(row):
                session.commit()
                return None
            active = row.status == DeepEvaluationStatus.PROCESSING
            attempt = row.attempt_count if active else row.attempt_count + 1
            if attempt > 2:
                repo.finish_invalid(row, corrective=True, error_code="attempt_budget_exhausted")
                session.commit()
                return None
            active_corrective = (
                row.active_corrective_attempt
                if active
                else (1 if corrective or attempt == 2 else 0)
            )
            messages = (
                build_corrective_messages(
                    input_json=input_value.model_dump_json(),
                    response_schema=get_deep_evaluation_schema(),
                    errors=("previous_attempt_invalid",),
                )
                if active_corrective
                else build_deep_messages(
                    input_json=input_value.model_dump_json(),
                    response_schema=get_deep_evaluation_schema(),
                )
            )
            request = StructuredGenerationRequest(
                operation_id=row.id,
                input_hash=input_hash,
                prompt_version=PROMPT_VERSION,
                schema_version=SCHEMA_VERSION,
                corrective_attempt=cast(Literal[0, 1], active_corrective),
                messages=messages,
                response_schema=get_deep_evaluation_schema(),
                capability=CAPABILITY,
                generation={
                    "max_tokens": self._settings.deep_evaluation_max_tokens,
                    "temperature": self._settings.deep_evaluation_temperature,
                    "top_p": self._settings.deep_evaluation_top_p,
                    "top_k": self._settings.deep_evaluation_top_k,
                },
                trace={
                    "job_id": job.id,
                    "deep_evaluation_id": row.id,
                    "score_id": score.id,
                    "prompt_version": PROMPT_VERSION,
                    "schema_version": SCHEMA_VERSION,
                },
            )
            fingerprint = _fingerprint(request)
            if (
                active
                and row.request_fingerprint is not None
                and row.request_fingerprint != fingerprint
            ):
                raise RuntimeError("request_reconstruction_mismatch")
            repo.set_processing(
                row, attempt=attempt, corrective=active_corrective, fingerprint=fingerprint
            )
            session.commit()
            return PreparedDeepEvaluation(
                row.id, operation_key, input_hash, attempt, fingerprint, input_value, request
            )

    async def execute(self, prepared: PreparedDeepEvaluation) -> DeepEvaluationExecution:
        try:
            return DeepEvaluationExecution(
                prepared, result=await self._provider.generate_structured(prepared.request)
            )
        except ProviderError as exc:
            return DeepEvaluationExecution(prepared, error=exc)

    def finalize(self, execution: DeepEvaluationExecution) -> FinalizedDeepEvaluation:
        with self._session_factory() as session:
            row = session.get(JobDeepEvaluation, execution.prepared.evaluation_id)
            if row is None:
                raise LookupError("deep evaluation not found")
            if (
                row.attempt_count != execution.prepared.attempt
                or row.request_fingerprint != execution.prepared.fingerprint
            ):
                raise RuntimeError("request_reconstruction_mismatch")
            repo = DeepEvaluationRepository(session)
            if repo.terminal(row):
                return FinalizedDeepEvaluation(row.id, row.status)
            if execution.error is not None:
                if execution.error.retryable:
                    row.status = DeepEvaluationStatus.PROCESSING
                else:
                    repo.finish_failure(
                        row,
                        error_class=_safe(execution.error.error_class),
                        error_code=_safe(execution.error.code),
                        task_id=execution.error.provider_task_id,
                    )
                session.commit()
                return FinalizedDeepEvaluation(row.id, row.status)
            assert execution.result is not None
            try:
                payload = validate_result(execution.result.content, execution.prepared.input)
            except Exception:
                if execution.prepared.attempt < 2:
                    repo.finish_invalid(row, corrective=False, error_code="provider_output_invalid")
                    session.commit()
                    return FinalizedDeepEvaluation(row.id, row.status, retry_corrective=True)
                repo.finish_invalid(row, corrective=True, error_code="corrective_invalid")
                session.commit()
                return FinalizedDeepEvaluation(row.id, row.status)
            adjustment, final_score = calculate_adjustment(
                row.job_score.preliminary_score
                if row.job_score
                else execution.prepared.input.preliminary.score,
                payload.fit_score,
                self._policy.adjustment_limit,
            )
            repo.finish_valid(
                row,
                payload=payload.model_dump(mode="json"),
                adjustment=adjustment,
                final_score=final_score,
                task_id=execution.result.provider_task_id,
                model_identifier=execution.result.model_identifier,
                finish_reason=execution.result.finish_reason,
                usage=execution.result.usage,
            )
            session.commit()
            return FinalizedDeepEvaluation(row.id, row.status)


def _fingerprint(request: StructuredGenerationRequest) -> str:
    return hashlib.sha256(
        json.dumps(request.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _safe(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".:-_" else "_" for char in value)[:128]
