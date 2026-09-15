"""Restart-safe feedback eligibility pass over the pre-acquisition corpus."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import Job, JobSearchRun, RunJob
from role_radar.domain.enums import RunJobStage, RunJobStatus
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.matching.feedback_eligibility import (
    POLICY_VERSION,
    serialize_feedback_eligibility,
)
from role_radar.repositories.runs import RunRepository
from role_radar.services.matching_service import MatchingService
from role_radar.services.pipeline_extraction import PipelineExtractionService

MANIFEST_KEY = "feedback_eligibility_reprocessing"
PURPOSE = "feedback_eligibility_reprocess"


def _binding(profile: Any) -> dict[str, Any]:
    return {
        "profile_id": profile.id,
        "row_version": profile.version,
        "schema_version": profile.schema_version,
        "canonical_profile_sha256": canonical_profile_sha256(profile.profile_json),
    }


class EligibilityReprocessingService:
    def __init__(
        self, session_factory: Callable[[], Session], extraction: PipelineExtractionService
    ) -> None:
        self._session_factory = session_factory
        self._extraction = extraction

    def _manifest(self, run: Any, profile: Any) -> dict[str, Any]:
        current = dict((run.stats_json or {}).get(MANIFEST_KEY) or {})
        binding = _binding(profile)
        cutoff = current.get("cutoff_utc")
        if current and (
            current.get("policy_version") != POLICY_VERSION
            or current.get("profile_binding") != binding
        ):
            raise RuntimeError("feedback_eligibility_manifest_mismatch")
        if cutoff is None:
            cutoff = datetime.now(UTC).isoformat()
        with self._session_factory() as session:
            total = len(
                list(
                    session.scalars(
                        select(Job.id).where(Job.created_at <= datetime.fromisoformat(cutoff))
                    )
                )
            )
        return {
            "policy_version": POLICY_VERSION,
            "profile_binding": binding,
            "cutoff_utc": cutoff,
            "total": total,
            "pending": total,
            "completed": 0,
            "eligible": 0,
            "excluded": 0,
            "reason_counts": {},
            "complete": False,
            **current,
        }

    def _save_manifest(self, run_id: str, manifest: dict[str, Any]) -> None:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            stats = dict(run.stats_json or {})
            stats[MANIFEST_KEY] = manifest
            run.stats_json = stats
            session.commit()

    def _recompute(self, run_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        with self._session_factory() as session:
            rows = list(
                session.scalars(
                    select(RunJob).where(
                        RunJob.run_id == run_id, RunJob.stage == RunJobStage.PREFILTERED
                    )
                )
            )
        valid = [r for r in rows if self._valid_checkpoint(r, manifest)]
        eligible = sum(
            bool((r.outcome_json or {}).get("decision", {}).get("eligible")) for r in valid
        )
        reasons: dict[str, int] = {}
        for row in valid:
            for reason in (row.outcome_json or {}).get("decision", {}).get("reason_codes", []):
                reasons[reason] = reasons.get(reason, 0) + 1
        manifest.update(
            completed=len(valid),
            pending=max(0, manifest["total"] - len(valid)),
            eligible=eligible,
            excluded=len(valid) - eligible,
            reason_counts=dict(sorted(reasons.items())),
            complete=len(valid) == manifest["total"],
        )
        self._save_manifest(run_id, manifest)
        return manifest

    @staticmethod
    def _valid_checkpoint(row: RunJob, manifest: dict[str, Any]) -> bool:
        outcome = row.outcome_json or {}
        decision = outcome.get("decision") or {}
        return (
            row.status is RunJobStatus.SUCCEEDED
            and outcome.get("purpose") == PURPOSE
            and decision.get("policy_version") == manifest["policy_version"]
            and decision.get("profile_binding") == manifest["profile_binding"]
            and isinstance(decision.get("input_sha256"), str)
        )

    async def process(self, run_id: str) -> dict[str, Any]:
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None or run.profile_id is None:
                raise RuntimeError("feedback_eligibility_profile_missing")
            profile = MatchingService(session).resolve_profile(run.profile_id)
        manifest = self._manifest(run, profile)
        self._save_manifest(run_id, manifest)
        with self._session_factory() as session:
            cutoff = datetime.fromisoformat(manifest["cutoff_utc"])
            jobs = list(
                session.scalars(
                    select(Job).where(Job.created_at <= cutoff).order_by(Job.created_at, Job.id)
                )
            )
        for job in jobs:
            with self._session_factory() as session:
                existing = session.scalar(
                    select(RunJob).where(
                        RunJob.run_id == run_id,
                        RunJob.job_id == job.id,
                        RunJob.stage == RunJobStage.PREFILTERED,
                    )
                )
                if existing is not None and self._valid_checkpoint(existing, manifest):
                    continue
            try:
                prepared = self._extraction.prepare(job.id)
                if prepared is not None:
                    finalized = self._extraction.finalize(await self._extraction.execute(prepared))
                    if finalized.retry_corrective:
                        prepared = self._extraction.prepare(job.id, corrective=True)
                        if prepared is not None:
                            self._extraction.finalize(await self._extraction.execute(prepared))
            except Exception:
                pass
            with self._session_factory() as session:
                score, decision = MatchingService(session).score_job_with_eligibility(
                    job_id=job.id, profile_id=manifest["profile_binding"]["profile_id"]
                )
                RunRepository(session).update_run_job(
                    run_id=run_id,
                    job_id=job.id,
                    stage=RunJobStage.PREFILTERED,
                    status=RunJobStatus.SUCCEEDED,
                    outcome_json={
                        "purpose": PURPOSE,
                        "decision": serialize_feedback_eligibility(decision),
                        "job_score_id": score.id,
                    },
                )
                session.commit()
            manifest = self._recompute(run_id, manifest)
        return self._recompute(run_id, manifest)
