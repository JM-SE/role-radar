"""Superficie de feedback del producto actual sobre candidatos de discovery."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import Job, JobSearchRun, RunJob
from role_radar.discovery.relevance import (
    RELEVANCE_VERSION,
    UNRELATED,
    RelevanceCandidate,
    rank_candidates,
)
from role_radar.domain.enums import RunJobStage, RunJobStatus
from role_radar.evaluation.blind_labeling.contracts import Decision, Label, PilotItem
from role_radar.evaluation.blind_labeling.display import render_pilot_item
from role_radar.evaluation.blind_labeling.display_policy import DISPLAY_VISIBLE_EMAIL_PATTERN
from role_radar.evaluation.blind_labeling.interaction import compose_rendered_item
from role_radar.evaluation.blind_labeling.validation import ValidationError, validate_decision
from role_radar.matching.product_eligibility import validate_product_eligibility
from role_radar.repositories.discovery import DiscoveryRepository
from role_radar.repositories.feedback import FeedbackRepository


@dataclass(frozen=True, slots=True)
class FeedbackCandidate:
    """Candidato de discovery apto para feedback humano."""

    job_id: str
    title: str
    company: str
    location: str | None
    description: str


@dataclass(frozen=True, slots=True)
class FeedbackItem:
    """Candidato con relevancia recomputada y última decisión guardada."""

    job_id: str
    title: str
    company: str
    band: str | None
    matched_phrases: tuple[str, ...]
    text_sha256: str | None
    revision: int
    decision: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class FeedbackSurface:
    """Vista ordenada y acotada para el ciclo de feedback."""

    run_id: str
    cycle_id: str | None
    planner_version: str | None
    policy_version: str | None
    relevance_version: str
    approved_phrases: tuple[str, ...]
    items: tuple[FeedbackItem, ...]
    unrelated_count: int
    excluded_count: int
    eligibility: dict[str, Any]


def _is_discovery_row(row: RunJob) -> bool:
    outcome = row.outcome_json or {}
    return (
        row.stage is RunJobStage.DEDUPLICATED
        and row.status is RunJobStatus.SUCCEEDED
        and outcome.get("acquisition") == "discovery"
    )


def collect_candidates(
    session: Session, run_id: str, *, scope: Literal["all", "current", "reprocessed"] = "all"
) -> tuple[FeedbackCandidate, ...]:
    """Return the exact run's eligible evidence pool for the selected scope."""
    stages = {
        "current": (RunJobStage.SCORED,),
        "reprocessed": (RunJobStage.PREFILTERED,),
        "all": (RunJobStage.SCORED, RunJobStage.PREFILTERED),
    }
    if scope not in stages:
        raise ValueError("feedback_scope_invalid")
    rows = session.execute(
        select(RunJob, Job)
        .join(Job, Job.id == RunJob.job_id)
        .where(
            RunJob.run_id == run_id,
            RunJob.stage.in_(stages[scope]),
            RunJob.status == RunJobStatus.SUCCEEDED,
        )
        .order_by(RunJob.created_at, RunJob.job_id)
    ).all()
    candidates: list[FeedbackCandidate] = []
    seen: set[str] = set()
    for run_job, job in rows:
        if job.id in seen:
            continue
        outcome = run_job.outcome_json or {}
        if not isinstance(outcome.get("product_eligibility"), dict):
            continue
        seen.add(job.id)
        candidates.append(
            FeedbackCandidate(
                job_id=job.id,
                title=job.title or "",
                company=job.company or "",
                location=job.location,
                description=job.description or "",
            )
        )
    return tuple(candidates)


def _approved_phrases(session: Session, run_id: str) -> tuple[str, ...]:
    cycle = DiscoveryRepository(session).get_cycle_for_run(run_id)
    if cycle is None:
        return ()
    snapshot = cycle.profile_snapshot_json or {}
    phrases = snapshot.get("approved_phrases", ())
    return tuple(phrase for phrase in phrases if isinstance(phrase, str) and phrase)


def _renderable(item: FeedbackCandidate) -> bool:
    return bool(
        item.job_id and item.title.strip() and item.company.strip() and item.description.strip()
    )


def _eligibility_for_run(
    session: Session,
    run: JobSearchRun,
    candidates: tuple[FeedbackCandidate, ...],
    cycle: Any,
    *,
    scope: Literal["all", "current", "reprocessed"],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Validate exact-run product decisions against its frozen manifest."""
    manifest = (run.stats_json or {}).get("product_eligibility_reprocessing") or {}
    binding = manifest.get("profile_binding") or {}
    stages = {
        "current": (RunJobStage.SCORED,),
        "reprocessed": (RunJobStage.PREFILTERED,),
        "all": (RunJobStage.SCORED, RunJobStage.PREFILTERED),
    }[scope]
    rows = {
        row.job_id: row
        for row in session.scalars(
            select(RunJob)
            .where(
                RunJob.run_id == run.id,
                RunJob.stage.in_(stages),
                RunJob.status == RunJobStatus.SUCCEEDED,
            )
            .order_by(RunJob.stage)
        )
    }
    decisions: dict[str, dict[str, Any]] = {}
    counts: dict[str, Any] = {"eligible": 0, "excluded": 0, "reason_counts": {}}
    for candidate in candidates:
        row = rows.get(candidate.job_id)
        decision = (row.outcome_json or {}).get("product_eligibility") if row else None
        valid = validate_product_eligibility(decision, profile_binding=binding or None)
        if valid and isinstance(decision, dict):
            decisions[candidate.job_id] = decision
            if decision.get("eligible") is True:
                counts["eligible"] += 1
            else:
                counts["excluded"] += 1
                for reason in decision.get("reason_codes", []):
                    counts["reason_counts"][reason] = counts["reason_counts"].get(reason, 0) + 1
        else:
            counts["excluded"] += 1
            reason = "missing_eligibility" if row is None else "malformed_eligibility"
            counts["reason_counts"][reason] = counts["reason_counts"].get(reason, 0) + 1
    counts["reason_counts"] = dict(sorted(counts["reason_counts"].items()))
    return decisions, counts


def build_surface(
    session: Session, run_id: str, *, scope: Literal["all", "current", "reprocessed"] = "all"
) -> FeedbackSurface:
    """Assemble the selected immutable current/history feedback surface."""
    run = session.get(JobSearchRun, run_id)
    if run is None:
        raise LookupError("run not found")
    cycle = DiscoveryRepository(session).get_cycle_for_run(run_id)
    approved = _approved_phrases(session, run_id)
    candidates = collect_candidates(session, run_id, scope=scope)
    admitted, eligibility = _eligibility_for_run(session, run, candidates, cycle, scope=scope)
    if scope == "reprocessed":
        scores = {
            row.job_id: (row.outcome_json or {}).get("job_score_id")
            for row in session.scalars(
                select(RunJob).where(
                    RunJob.run_id == run_id,
                    RunJob.stage == RunJobStage.PREFILTERED,
                    RunJob.status == RunJobStatus.SUCCEEDED,
                )
            )
        }
        jobs = {
            job.id: job
            for job in session.scalars(
                select(Job).where(Job.id.in_([item.job_id for item in candidates]))
            )
        }
        candidates = tuple(
            item
            for _, item in sorted(
                (
                    (
                        scores.get(item.job_id) is None,
                        scores.get(item.job_id),
                        -(
                            jobs[item.job_id].first_seen_at.timestamp()
                            if jobs.get(item.job_id) and jobs[item.job_id].first_seen_at
                            else 0.0
                        ),
                        item.job_id,
                    ),
                    item,
                )
                for item in candidates
                if item.job_id in admitted
            )
        )
    else:
        candidates = tuple(item for item in candidates if item.job_id in admitted)
    renderable = [item for item in candidates if _renderable(item)]
    latest = FeedbackRepository(session).latest_for_run(run_id)
    if approved:
        ranked = rank_candidates(
            [
                RelevanceCandidate(
                    job_id=item.job_id,
                    title=item.title,
                    company=item.company,
                    description=item.description,
                )
                for item in renderable
            ],
            approved_phrases=approved,
        )
        by_id = {item.job_id: item for item in (*ranked.relevant, *ranked.near_miss)}
        ordered = [item for item in renderable if item.job_id in by_id]
        ordered.sort(
            key=lambda item: (
                0 if by_id[item.job_id].band == "relevant" else 1,
                -len(by_id[item.job_id].matched_phrases),
                item.job_id,
            )
        )
        unrelated = [item for item in renderable if item.job_id not in by_id]
        unrelated_count = ranked.unrelated_count
        excluded_count = len(candidates) - len(renderable)
    else:
        by_id = {}
        ordered = list(renderable)
        unrelated = []
        unrelated_count = 0
        excluded_count = len(candidates) - len(renderable)
    items: list[FeedbackItem] = []
    for item in ordered:
        ranked_item = by_id.get(item.job_id)
        stored = latest.get(item.job_id)
        items.append(
            FeedbackItem(
                job_id=item.job_id,
                title=item.title,
                company=item.company,
                band=ranked_item.band if ranked_item is not None else None,
                matched_phrases=ranked_item.matched_phrases if ranked_item is not None else (),
                text_sha256=ranked_item.text_sha256 if ranked_item is not None else None,
                revision=stored.revision if stored is not None else 0,
                decision=(
                    {
                        "label": stored.label,
                        "primary_reason": stored.primary_reason,
                        "secondary_reasons": list(stored.secondary_reasons_json or ()),
                        "note": stored.note,
                        "revision": stored.revision,
                    }
                    if stored is not None
                    else None
                ),
            )
        )
    for item in sorted(unrelated, key=lambda entry: entry.job_id):
        stored = latest.get(item.job_id)
        items.append(
            FeedbackItem(
                job_id=item.job_id,
                title=item.title,
                company=item.company,
                band=UNRELATED if approved else None,
                matched_phrases=(),
                text_sha256=None,
                revision=stored.revision if stored is not None else 0,
                decision=(
                    {
                        "label": stored.label,
                        "primary_reason": stored.primary_reason,
                        "secondary_reasons": list(stored.secondary_reasons_json or ()),
                        "note": stored.note,
                        "revision": stored.revision,
                    }
                    if stored is not None
                    else None
                ),
            )
        )
    return FeedbackSurface(
        run_id=run_id,
        cycle_id=cycle.id if cycle is not None else None,
        planner_version=cycle.planner_version if cycle is not None else None,
        policy_version=cycle.policy_version if cycle is not None else None,
        relevance_version=RELEVANCE_VERSION,
        approved_phrases=approved,
        items=tuple(items),
        unrelated_count=unrelated_count,
        excluded_count=excluded_count,
        eligibility=eligibility,
    )


_FEEDBACK_VISIBLE_URL = re.compile(
    r"(?:https?://|www\.|mailto:|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?=[/?#]))[^\s<]*",
    re.IGNORECASE,
)


def _feedback_preview(description: str) -> str:
    """Redact external references only in the feedback display copy."""

    return DISPLAY_VISIBLE_EMAIL_PATTERN.sub(
        "[EMAIL]", _FEEDBACK_VISIBLE_URL.sub("[URL]", description)
    )


def render_candidate(candidate: FeedbackCandidate, *, index: int, total: int) -> str:
    """Compone un candidato con display v2 sin tocar la CLI histórica."""

    rendered = render_pilot_item(
        PilotItem(
            opaque_id=candidate.job_id,
            title=candidate.title,
            company=candidate.company,
            location=candidate.location,
            description=_feedback_preview(candidate.description),
        )
    )
    return compose_rendered_item(rendered, index=index, total=total)


def submit_feedback(
    session: Session,
    *,
    run_id: str,
    job_id: str,
    label: str,
    primary_reason: str,
    secondary_reasons: Sequence[str] = (),
    note: str | None = None,
    reviewer: str | None = None,
    expected_revision: int | None = None,
) -> tuple[Any, bool]:
    """Valida con el contrato blind y anexa una revisión idempotente."""

    # Single-user product: the interactive CLI has no login, so an omitted
    # reviewer is the local operator rather than unknown provenance.
    reviewer_identity = reviewer or "operator"

    try:
        parsed_label = Label(label)
    except ValueError:
        raise ValidationError("label_invalid") from None
    decision = validate_decision(
        Decision(
            label=parsed_label,
            primary_reason=primary_reason,
            secondary_reasons=tuple(secondary_reasons),
            note=note,
        )
    )
    run = session.get(JobSearchRun, run_id)
    if run is None:
        raise LookupError("run not found")
    surface = build_surface(session, run_id)
    bands = {item.job_id: item.band for item in surface.items}
    texts = {item.job_id: item.text_sha256 for item in surface.items}
    if job_id not in bands:
        raise LookupError("feedback job not in run")
    binding = ((run.stats_json or {}).get("product_eligibility_reprocessing") or {}).get(
        "profile_binding"
    ) or {}
    cycle = DiscoveryRepository(session).get_cycle_for_run(run_id)
    snapshot = dict(cycle.profile_snapshot_json) if cycle is not None else {}
    policy_hash = snapshot.get("policy_sha256")
    if not isinstance(policy_hash, str):
        policy_hash = None
    return FeedbackRepository(session).submit(
        run_id=run_id,
        job_id=job_id,
        label=decision.label.value,
        primary_reason=decision.primary_reason,
        secondary_reasons=decision.secondary_reasons,
        note=decision.note,
        relevance_band=bands[job_id],
        policy_version=surface.policy_version,
        profile_id=binding.get("profile_id") if isinstance(binding, dict) else None,
        row_version=binding.get("row_version") if isinstance(binding, dict) else None,
        schema_version=binding.get("schema_version") if isinstance(binding, dict) else None,
        canonical_profile_sha256=binding.get("canonical_profile_sha256")
        if isinstance(binding, dict)
        else None,
        policy_hash=policy_hash,
        relevance_version=surface.relevance_version,
        text_sha256=texts[job_id],
        reviewer=reviewer_identity,
        expected_revision=expected_revision,
    )


def summarize(
    session: Session,
    run_id: str,
    *,
    scope: Literal["all", "current", "reprocessed"] = "all",
) -> dict[str, Any]:
    """Summarize labels, reasons, and selected scope without job text."""
    surface = build_surface(session, run_id, scope=scope)
    base = FeedbackRepository(session).summary(run_id)
    bands: dict[str, int] = {}
    for item in surface.items:
        if item.decision is not None:
            key = item.band or "unranked"
            bands[key] = bands.get(key, 0) + 1
    return {
        **base,
        "scope": scope,
        "cycle_id": surface.cycle_id,
        "planner_version": surface.planner_version,
        "policy_version": surface.policy_version,
        "candidates": len(surface.items),
        "unrelated_count": surface.unrelated_count,
        "excluded_count": surface.excluded_count,
        "decided_bands": bands,
        "eligibility": surface.eligibility,
    }
