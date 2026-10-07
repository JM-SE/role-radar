"""Shared synchronous RawJob writer used by ATS collection and discovery."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import CandidateProfile, JobSearchRun, Source
from role_radar.dedup.service import DedupService
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import RunJobStage, RunJobStatus
from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256
from role_radar.execution_budget import CANARY_BUDGET, CANARY_LIMITS, checkpoint_counts
from role_radar.matching.contracts import JobFacts, ProfileBinding, serialize_profile_intake
from role_radar.matching.policy import ScoringPolicyV1
from role_radar.matching.profile_intake import evaluate_profile_intake
from role_radar.matching.signals import role_match
from role_radar.matching.transient_clarification import (
    MAX_ATTEMPTS_PER_RUN,
    TransientDescriptionEvidence,
    clarify_description,
)
from role_radar.normalization.jobs import normalize_raw_job
from role_radar.repositories.jobs import JobRepository
from role_radar.repositories.runs import RunRepository


@dataclass(frozen=True, slots=True)
class AcquiredWriteResult:
    accepted: int
    new_jobs: int
    duplicates: int
    prefiltered: int
    profile_rejected: int
    clarification_attempts: int
    profile_reason_counts: tuple[tuple[str, int], ...]
    job_ids: tuple[str, ...]


class AcquiredJobWriter:
    """All ORM access is synchronous and the caller owns the transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._jobs = JobRepository(session)
        self._runs = RunRepository(session)
        self._dedup = DedupService(self._jobs)

    def _intake_context(
        self, run_id: str, source_id: str
    ) -> tuple[CandidateProfileV1, ProfileBinding, Source, dict[str, object]]:
        run = self._session.scalar(select(JobSearchRun).where(JobSearchRun.id == run_id))
        if run is None or run.profile_id is None:
            raise RuntimeError("profile_intake_run_invalid")
        profile = self._session.scalar(
            select(CandidateProfile).where(CandidateProfile.id == run.profile_id)
        )
        if profile is None or profile.schema_version != 1:
            raise RuntimeError("profile_intake_profile_invalid")
        try:
            canonical = CandidateProfileV1.model_validate(profile.profile_json)
            binding = ProfileBinding(
                profile_id=profile.id,
                row_version=profile.version,
                schema_version=profile.schema_version,
                canonical_profile_sha256=canonical_profile_sha256(profile.profile_json),
            )
        except Exception as exc:
            raise RuntimeError("profile_intake_profile_invalid") from exc
        source = self._session.scalar(select(Source).where(Source.id == source_id))
        configuration = source.configuration if source is not None else None
        if source is None or not isinstance(configuration, dict):
            raise RuntimeError("profile_intake_source_invalid")
        return canonical, binding, source, configuration

    def write(
        self,
        *,
        run_id: str,
        source_id: str,
        raw_jobs: tuple[RawJob, ...],
        acquisition: str = "ats",
        cycle_id: str | None = None,
        max_clarification_attempts: int = MAX_ATTEMPTS_PER_RUN,
    ) -> AcquiredWriteResult:
        profile, binding, source, configuration = self._intake_context(run_id, source_id)
        new_jobs = duplicates = prefiltered = profile_rejected = clarification_attempts = 0
        reason_counts: dict[str, int] = {}
        ids: list[str] = []
        for raw_job in raw_jobs:
            normalized = normalize_raw_job(raw_job)
            if (
                not normalized.title
                or not normalized.description
                or not (normalized.application_url or normalized.source_url)
            ):
                prefiltered += 1
                continue
            decision = evaluate_profile_intake(
                profile,
                normalized,
                source_type=source.type.value,
                source_configuration=configuration,
                profile_binding=binding,
            )
            clarification: TransientDescriptionEvidence | None = None
            role_points = role_match(
                profile,
                JobFacts(title=normalized.title, title_provenance="ats"),
                ScoringPolicyV1().maxima["role_match"],
            )[0].points
            clarification_eligible_reasons = {
                "remote_policy_unknown",
                "region_unknown",
            }
            if (
                raw_job.description
                and clarification_attempts < max_clarification_attempts
                and role_points > 0
                and (
                    decision.eligible
                    or set(decision.reason_codes).issubset(clarification_eligible_reasons)
                )
                and self._runs.reserve_clarification_attempt(
                    run_id, max_attempts=MAX_ATTEMPTS_PER_RUN
                )
            ):
                clarification_attempts += 1
                clarification = clarify_description(normalized.description)
                if clarification is not None:
                    decision = evaluate_profile_intake(
                        profile,
                        normalized,
                        source_type=source.type.value,
                        source_configuration=configuration,
                        profile_binding=binding,
                        clarification=clarification,
                    )
            if not decision.eligible or decision.application_url is None:
                profile_rejected += 1
                for reason in decision.reason_codes:
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
                if (
                    decision.application_url is None
                    and "application_url_missing_or_invalid" not in decision.reason_codes
                ):
                    reason_counts["application_url_missing_or_invalid"] = (
                        reason_counts.get("application_url_missing_or_invalid", 0) + 1
                    )
                continue
            run = self._session.get(JobSearchRun, run_id)
            if run is not None and run.canary_budget_json is not None:
                if run.canary_budget_json != CANARY_BUDGET:
                    raise RuntimeError("canary_budget_missing_or_changed")
                checkpoint = dict(run.canary_checkpoint_json or {})
                counts = dict(checkpoint_counts(checkpoint))
                if counts.get("accepted_items", 0) >= CANARY_LIMITS["accepted_items"]:
                    break
                counts["accepted_items"] = counts.get("accepted_items", 0) + 1
                checkpoint["version"] = 1
                checkpoint.setdefault("stage", "collection")
                checkpoint.setdefault("cursor", 0)
                checkpoint["counts"] = counts
                checkpoint.setdefault("reservations", [])
                run.canary_checkpoint_json = checkpoint
            normalized = normalized.model_copy(update={"application_url": decision.application_url})
            intake_evidence = dict(decision.intake_evidence or {})
            raw_payload = {**(raw_job.structured_data or {}), **intake_evidence}
            if clarification is not None:
                raw_payload = dict(raw_job.structured_data or {})
                raw_payload["role_radar_intake_clarification"] = clarification.canonical_dict()
                raw_payload["role_radar_profile_intake"] = serialize_profile_intake(decision)
            resolved = self._dedup.resolve(
                normalized=normalized,
                source_id=source_id,
                raw_payload=raw_payload,
            )
            ids.append(resolved.job.id)
            if resolved.is_new:
                new_jobs += 1
            else:
                duplicates += 1
            outcome: dict[str, Any] = {
                "profile_intake": serialize_profile_intake(decision),
            }
            if acquisition == "discovery" and cycle_id is not None:
                outcome.update(
                    {"acquisition": "discovery", "cycle_id": cycle_id, "source_id": source_id}
                )
            for stage in (RunJobStage.COLLECTED, RunJobStage.NORMALIZED, RunJobStage.DEDUPLICATED):
                self._runs.update_run_job(
                    run_id=run_id,
                    job_id=resolved.job.id,
                    stage=stage,
                    status=RunJobStatus.SUCCEEDED,
                    outcome_json=outcome if stage is RunJobStage.DEDUPLICATED else None,
                )
        return AcquiredWriteResult(
            accepted=len(ids),
            new_jobs=new_jobs,
            duplicates=duplicates,
            prefiltered=prefiltered,
            profile_rejected=profile_rejected,
            clarification_attempts=clarification_attempts,
            profile_reason_counts=tuple(sorted(reason_counts.items())),
            job_ids=tuple(ids),
        )
