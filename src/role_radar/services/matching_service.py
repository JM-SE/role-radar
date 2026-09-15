"""Thin synchronous orchestration around the pure matching core."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from role_radar.db.models import CandidateProfile, Job, JobScore, JobSourceReference
from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256
from role_radar.matching.contracts import Ambiguity, FeedbackEligibilityDecision, ProfileBinding
from role_radar.matching.engine import score_job
from role_radar.matching.facts import (
    ExtractionSnapshot,
    JobSnapshot,
    SourceReferenceSnapshot,
    build_job_facts,
)
from role_radar.matching.feedback_eligibility import evaluate_feedback_eligibility
from role_radar.matching.profile_adapter import adapt_legacy_profile
from role_radar.repositories.scores import ScoreRepository


def _source_authority(source_type: str | None) -> int:
    """Stable local authority ordering for ATS snapshots."""
    return {
        "greenhouse": 100,
        "lever": 100,
        "ashby": 100,
        "workable": 100,
        "manual": 50,
    }.get(source_type or "", 0)


class MatchingService:
    """Load ORM state, call pure functions, and persist one immutable result."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def resolve_profile(self, profile_id: str | None = None) -> CandidateProfile:
        if profile_id is not None:
            profile = self._session.get(CandidateProfile, profile_id)
            if profile is None:
                raise LookupError("profile not found")
            return profile
        profiles = list(
            self._session.scalars(
                select(CandidateProfile)
                .where(CandidateProfile.is_active.is_(True))
                .order_by(CandidateProfile.created_at, CandidateProfile.id)
            )
        )
        if len(profiles) != 1:
            raise ValueError("profile_id is required unless exactly one active profile exists")
        return profiles[0]

    def score_job(self, *, job_id: str, profile_id: str | None = None) -> JobScore:
        score, _ = self._score_snapshot(job_id=job_id, profile_id=profile_id)
        return score

    def score_job_with_eligibility(
        self, *, job_id: str, profile_id: str | None = None
    ) -> tuple[JobScore, FeedbackEligibilityDecision]:
        return self._score_snapshot(job_id=job_id, profile_id=profile_id)

    def _score_snapshot(
        self, *, job_id: str, profile_id: str | None = None
    ) -> tuple[JobScore, FeedbackEligibilityDecision]:
        job = self._session.scalar(
            select(Job)
            .where(Job.id == job_id)
            .options(
                selectinload(Job.source_references).selectinload(JobSourceReference.source),
                selectinload(Job.extractions),
            )
        )
        if job is None:
            raise LookupError("job not found")
        profile = self.resolve_profile(profile_id)
        adapted_ambiguities: tuple[Ambiguity, ...] = ()
        if profile.schema_version == 0:
            adapted = adapt_legacy_profile(profile.profile_json)
            canonical = adapted.profile
            adapted_ambiguities = adapted.ambiguities
        else:
            canonical = CandidateProfileV1.model_validate(profile.profile_json)

        references = tuple(
            SourceReferenceSnapshot(
                id=reference.id,
                raw_payload=reference.raw_payload,
                collected_at=reference.collected_at.isoformat(),
                authority=_source_authority(
                    reference.source.type.value if reference.source else None
                ),
            )
            for reference in job.source_references
        )
        extractions = tuple(
            ExtractionSnapshot(
                id=extraction.id,
                input_hash=extraction.input_hash,
                validation_status=extraction.validation_status.value,
                extraction_json=extraction.extraction_json,
                updated_at=extraction.updated_at.isoformat(),
                created_at=extraction.created_at.isoformat(),
            )
            for extraction in job.extractions
        )
        facts_result = build_job_facts(
            JobSnapshot(
                id=job.id,
                title=job.title,
                location=job.location,
                description_hash=job.description_hash,
                source_references=references,
                extractions=extractions,
            )
        )
        binding = ProfileBinding(
            profile_id=profile.id,
            row_version=profile.version,
            schema_version=profile.schema_version,
            canonical_profile_sha256=canonical_profile_sha256(profile.profile_json),
        )
        result = score_job(
            canonical,
            facts_result.facts,
            job_id=job.id,
            profile_id=profile.id,
            extraction_id=facts_result.facts.extraction_id,
            adaptation_ambiguities=tuple((*adapted_ambiguities, *facts_result.ambiguities)),
        )
        persisted = ScoreRepository(self._session).get_or_create_operation(
            result, job_id=job.id, profile_id=profile.id
        )
        decision = evaluate_feedback_eligibility(
            canonical, facts_result.facts, facts_result.ambiguities, binding
        )
        return persisted, decision

    def score_pending(self, *, limit: int, profile_id: str | None = None) -> list[JobScore]:
        profile = self.resolve_profile(profile_id)
        jobs = list(
            self._session.scalars(
                select(Job).order_by(Job.first_seen_at.desc(), Job.id).limit(limit)
            )
        )
        return [self.score_job(job_id=job.id, profile_id=profile.id) for job in jobs]
