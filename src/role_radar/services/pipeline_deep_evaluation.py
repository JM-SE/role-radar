"""F6 stage: materialize selection after scoring, then process durable rank order."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import (
    CandidateProfile,
    DeepEvaluationQueueItem,
    Job,
    JobDeepEvaluation,
    JobExtraction,
    JobScore,
    JobSearchRun,
    RunJob,
)
from role_radar.deep_evaluation.ambiguity_resolution import resolve_ambiguities_v1
from role_radar.deep_evaluation.contracts import DeepEvaluationCandidateV1
from role_radar.deep_evaluation.policy import DeepEvaluationPolicyV1
from role_radar.deep_evaluation.selector import select_candidates, selection_reason
from role_radar.domain.enums import RunJobStage, RunJobStatus
from role_radar.repositories.deep_queue import DeepQueueRepository
from role_radar.repositories.runs import RunRepository
from role_radar.services.deep_evaluation_service import DeepEvaluationService


class PipelineDeepEvaluationService:
    def __init__(
        self, session_factory: Callable[[], Session], *, provider: Any, settings: Any = None
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._deep = DeepEvaluationService(session_factory, provider=provider, settings=settings)
        self._policy = DeepEvaluationPolicyV1(
            high_score_min=settings.deep_evaluation_high_score_min if settings else 75,
            ambiguous_score_min=settings.deep_evaluation_ambiguous_score_min if settings else 55,
            ambiguous_score_max=settings.deep_evaluation_ambiguous_score_max if settings else 74,
            max_per_run=settings.deep_evaluation_max_per_run if settings else 10,
            adjustment_limit=settings.deep_evaluation_adjustment_limit if settings else 15,
            version=settings.deep_evaluation_policy_version if settings else "deep-selector-v1",
            ambiguity_resolution_version=(
                settings.deep_evaluation_ambiguity_resolution_version
                if settings
                else "ambiguity-resolution-v1"
            ),
        )

    def prepare_queue(self, run_id: str, job_ids: list[str]) -> list[DeepEvaluationQueueItem]:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None or run.profile_id is None:
                raise LookupError("run/profile not found")
            candidates: list[DeepEvaluationCandidateV1] = []
            scored_rows = list(
                session.scalars(
                    select(RunJob)
                    .where(RunJob.run_id == run_id, RunJob.stage == RunJobStage.SCORED)
                    .order_by(RunJob.job_id)
                )
            )
            for checkpoint in scored_rows:
                checkpoint_score_id = (checkpoint.outcome_json or {}).get("job_score_id")
                score = (
                    session.get(JobScore, checkpoint_score_id)
                    if isinstance(checkpoint_score_id, str)
                    else None
                )
                if score is None and checkpoint.status is RunJobStatus.SUCCEEDED:
                    score = session.scalar(
                        select(JobScore)
                        .where(
                            JobScore.job_id == checkpoint.job_id,
                            JobScore.profile_id == run.profile_id,
                        )
                        .order_by(JobScore.created_at.desc(), JobScore.id.asc())
                    )
                job = session.get(Job, checkpoint.job_id)
                extraction = (
                    session.get(JobExtraction, score.extraction_id)
                    if score and score.extraction_id
                    else None
                )
                profile = session.get(CandidateProfile, run.profile_id)
                if score is None or job is None or profile is None:
                    continue
                resolvable = (
                    resolve_ambiguities_v1(
                        score.ambiguity_json,
                        score.extraction_id,
                        {
                            "id": extraction.id,
                            "validation_status": extraction.validation_status.value,
                            "extraction_json": extraction.extraction_json,
                        },
                    )
                    if extraction
                    else ()
                )
                candidates.append(
                    DeepEvaluationCandidateV1(
                        job.id,
                        score.id,
                        profile.id,
                        extraction.id if extraction else None,
                        job.title,
                        job.company,
                        job.normalized_location,
                        job.first_seen_at,
                        score.preliminary_score,
                        score.eligible,
                        tuple(score.hard_blocker_json),
                        tuple(score.signal_json),
                        tuple(score.ambiguity_json),
                        resolvable,
                        self._policy.ambiguity_resolution_version,
                        extraction.extraction_json if extraction else None,
                        profile.profile_json,
                    )
                )
            selected = select_candidates(candidates, self._policy)
            queue = DeepQueueRepository(session)
            existing = {item.job_id: item for item in queue.list_for_run(run_id)}
            selected_ids = {item.candidate.job_id for item in selected}
            candidate_ids = {candidate.job_id for candidate in candidates}
            for selection in selected:
                candidate = selection.candidate
                if candidate.job_id not in existing:
                    codes = _codes(candidate)
                    queue.add(
                        run_id=run_id,
                        job_id=candidate.job_id,
                        job_score_id=candidate.job_score_id,
                        rank=selection.rank,
                        selection_reason=selection.reason,
                        selector_policy_version=self._policy.version,
                        selector_policy_hash=self._policy.policy_hash,
                        ambiguity_resolution_version=self._policy.ambiguity_resolution_version,
                        selection_input_hash=_selection_hash(candidate),
                        resolvable_ambiguity_codes_json=codes,
                    )
            for candidate in candidates:
                reason = selection_reason(
                    candidate.preliminary_score,
                    bool(candidate.resolvable_ambiguities),
                    self._policy,
                )
                if candidate.job_id in selected_ids:
                    status, code = RunJobStatus.PENDING, None
                else:
                    status, code = RunJobStatus.SKIPPED, reason
                RunRepository(session).update_run_job(
                    run_id=run_id,
                    job_id=candidate.job_id,
                    stage=RunJobStage.DEEP_EVALUATED,
                    status=status,
                    error_code=code,
                    outcome_json={
                        "reason": reason,
                        "resolvable_ambiguity_codes": _codes(candidate),
                    },
                )
            for job_id in job_ids:
                if job_id not in candidate_ids:
                    RunRepository(session).update_run_job(
                        run_id=run_id,
                        job_id=job_id,
                        stage=RunJobStage.DEEP_EVALUATED,
                        status=RunJobStatus.SKIPPED,
                        error_code="scoring_not_succeeded",
                        outcome_json={"reason": "scoring_not_succeeded"},
                    )
            session.commit()
            return queue.list_for_run(run_id)

    async def process(self, run_id: str) -> None:
        with self._session_factory() as session:
            queue = DeepQueueRepository(session).list_for_run(run_id)
            queue_ids = [(item.rank, item.job_score_id, item.job_id) for item in queue]
        for _rank, score_id, job_id in queue_ids:
            with self._session_factory() as session:
                row = session.scalar(
                    select(RunJob).where(
                        RunJob.run_id == run_id,
                        RunJob.job_id == job_id,
                        RunJob.stage == RunJobStage.DEEP_EVALUATED,
                    )
                )
                if row is not None and row.status in {RunJobStatus.SUCCEEDED, RunJobStatus.SKIPPED}:
                    continue
            try:
                prepared = self._deep.prepare(score_id)
                self._associate_evaluation(
                    run_id, job_id, prepared.evaluation_id if prepared else None, score_id
                )
                if prepared is None:
                    self._checkpoint(run_id, job_id, RunJobStatus.SUCCEEDED, "reused")
                    continue
                finalized = self._deep.finalize(await self._deep.execute(prepared))
                if finalized.retry_corrective:
                    corrective = self._deep.prepare(score_id, corrective=True)
                    if corrective is not None:
                        finalized = self._deep.finalize(await self._deep.execute(corrective))
                status = (
                    RunJobStatus.SUCCEEDED
                    if finalized.status.value == "valid"
                    else RunJobStatus.FAILED
                )
                self._checkpoint(run_id, job_id, status, finalized.status.value)
            except Exception as exc:
                self._checkpoint(run_id, job_id, RunJobStatus.FAILED, _safe(str(exc)))

    def _checkpoint(self, run_id: str, job_id: str, status: RunJobStatus, code: str) -> None:
        with self._session_factory() as session:
            RunRepository(session).update_run_job(
                run_id=run_id,
                job_id=job_id,
                stage=RunJobStage.DEEP_EVALUATED,
                status=status,
                error_code=None if status is RunJobStatus.SUCCEEDED else code,
                outcome_json={"result": code},
            )
            session.commit()

    def _associate_evaluation(
        self, run_id: str, job_id: str, evaluation_id: str | None, score_id: str
    ) -> None:
        with self._session_factory() as session:
            item = session.scalar(
                select(DeepEvaluationQueueItem).where(
                    DeepEvaluationQueueItem.run_id == run_id,
                    DeepEvaluationQueueItem.job_id == job_id,
                )
            )
            if item is None or item.evaluation_id is not None:
                return
            resolved = evaluation_id or session.scalar(
                select(JobDeepEvaluation.id)
                .where(JobDeepEvaluation.job_score_id == score_id)
                .order_by(JobDeepEvaluation.created_at.desc(), JobDeepEvaluation.id.asc())
                .limit(1)
            )
            if resolved is not None:
                item.evaluation_id = resolved
                session.commit()


def _codes(candidate: DeepEvaluationCandidateV1) -> list[str]:
    return list(dict.fromkeys(item.code for item in candidate.resolvable_ambiguities))[:16]


def _selection_hash(candidate: DeepEvaluationCandidateV1) -> str:
    payload = {
        "score": candidate.preliminary_score,
        "score_id": candidate.job_score_id,
        "extraction_id": candidate.extraction_id,
        "ambiguity_resolution_version": candidate.ambiguity_resolution_version,
        "resolvable": [
            (
                item.code,
                item.field,
                item.question,
                [(ref.reference, ref.excerpt) for ref in item.evidence],
            )
            for item in candidate.resolvable_ambiguities
        ],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _safe(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".:-_" else "_" for char in value)[:128]
