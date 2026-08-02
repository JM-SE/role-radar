"""Router de ofertas (GET /jobs, GET /jobs/{id}).

Sin POST /jobs en F1: la escritura de ofertas es excepción F1 (seed/tests),
la hará el worker en fases posteriores (política §11 de la spec).
"""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Query

from role_radar.api.deps import get_job_repository, get_profile_repository
from role_radar.api.schemas.jobs import (
    JobDeepEvaluationSummary,
    JobDetailResponse,
    JobResponse,
    JobScoreSummary,
)
from role_radar.db.models import CandidateProfile, Job, JobDeepEvaluation, JobScore
from role_radar.domain.enums import DeepDecision, JobStatus
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.profiles import ProfileRepository

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=list[JobResponse])
def list_jobs(
    status: JobStatus | None = None,
    company: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    profile_id: str | None = None,
    minimum_score: int | None = Query(None, ge=0, le=100),
    eligible: bool | None = None,
    requires_review: bool = False,
    decision: DeepDecision | None = None,
    minimum_effective_score: int | None = Query(None, ge=0, le=100),
    *,
    repo: Annotated[JobRepository, Depends(get_job_repository)],
    profiles: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> list[JobResponse]:
    """List ordinary jobs or rank them when any score parameter is present."""
    ranking = (
        profile_id is not None
        or minimum_score is not None
        or eligible is not None
        or requires_review
        or decision is not None
        or minimum_effective_score is not None
    )
    chosen_profile = _resolve_profile(profiles, profile_id, required=ranking)
    if ranking:
        assert chosen_profile is not None
        triples = repo.list_with_effective_scores(
            profile_id=chosen_profile.id,
            status=status,
            company=company,
            minimum_score=minimum_score,
            eligible=True if eligible is None else eligible,
            requires_review=requires_review,
            decision=decision,
            minimum_effective_score=minimum_effective_score,
            limit=limit,
            offset=offset,
        )
        return [_with_score(job, score, deep) for job, score, deep in triples]
    if chosen_profile is not None:
        optional_pairs = repo.list_with_optional_scores(
            profile_id=chosen_profile.id,
            status=status,
            company=company,
            limit=limit,
            offset=offset,
        )
        return [_with_score(job, score) for job, score in optional_pairs]
    jobs = repo.list(status=status, company=company, limit=limit, offset=offset)
    return [_with_score(job, None) for job in jobs]


@router.get("/{job_id}", response_model=JobDetailResponse)
def get_job(
    job_id: str,
    profile_id: str | None = None,
    *,
    repo: Annotated[JobRepository, Depends(get_job_repository)],
    profiles: Annotated[ProfileRepository, Depends(get_profile_repository)],
) -> JobDetailResponse:
    """Detalle de una oferta con sus referencias de fuente (404 si no existe)."""
    job = repo.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    chosen_profile = _resolve_profile(profiles, profile_id, required=False)
    score, deep = (
        repo.latest_score_with_deep(job_id=job_id, profile_id=chosen_profile.id)
        if chosen_profile
        else (None, None)
    )
    return cast(JobDetailResponse, _with_score(job, score, deep, detail=True))


def _resolve_profile(
    repo: ProfileRepository, profile_id: str | None, *, required: bool
) -> CandidateProfile | None:
    if profile_id:
        profile = repo.get(profile_id)
        if profile is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        return profile
    active = repo.list_active()
    if len(active) == 1:
        return active[0]
    if required:
        raise HTTPException(status_code=409, detail="profile_id is required")
    return None


def _deep_summary(deep: JobDeepEvaluation | None) -> JobDeepEvaluationSummary | None:
    if deep is None:
        return None
    return JobDeepEvaluationSummary(
        id=deep.id,
        status=deep.status.value,
        prompt_version=deep.prompt_version,
        schema_version=deep.schema_version,
        selector_policy_version=deep.selector_policy_version,
        fit_score=deep.fit_score,
        decision=deep.decision,
        strengths=deep.strengths_json or [],
        gaps=deep.gaps_json or [],
        model_concerns=deep.model_concerns_json or [],
        uncertainties=deep.uncertainties_json or [],
        recommended_action=deep.recommended_action,
        confidence=deep.confidence,
        adjustment=deep.adjustment,
        final_score=deep.final_score,
        created_at=deep.created_at,
    )


def _score_summary(
    score: JobScore | None, deep: JobDeepEvaluation | None = None
) -> JobScoreSummary | None:
    if score is None:
        return None
    return JobScoreSummary(
        id=score.id,
        profile_id=score.profile_id,
        extraction_id=score.extraction_id,
        scoring_version=score.scoring_version,
        policy_version=score.policy_version,
        score=score.preliminary_score,
        preliminary_score=score.preliminary_score,
        eligible=score.eligible,
        signals=score.signal_json,
        blockers=score.hard_blocker_json,
        ambiguities=score.ambiguity_json,
        created_at=score.created_at,
        effective_score=deep.final_score
        if deep is not None and deep.status.value == "valid" and deep.final_score is not None
        else score.preliminary_score,
        final_score=deep.final_score if deep is not None and deep.status.value == "valid" else None,
        decision=deep.decision if deep is not None and deep.status.value == "valid" else None,
        recommended_action=deep.recommended_action
        if deep is not None and deep.status.value == "valid"
        else None,
        confidence=deep.confidence if deep is not None and deep.status.value == "valid" else None,
        deep_evaluation=_deep_summary(deep),
    )


def _with_score(
    job: Job, score: JobScore | None, deep: JobDeepEvaluation | None = None, *, detail: bool = False
) -> JobResponse | JobDetailResponse:
    payload = JobDetailResponse.model_validate(job) if detail else JobResponse.model_validate(job)
    return payload.model_copy(update={"latest_score": _score_summary(score, deep)})
