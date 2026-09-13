"""Superficie de feedback del producto actual sobre candidatos de discovery."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

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
from role_radar.evaluation.blind_labeling.interaction import compose_rendered_item
from role_radar.evaluation.blind_labeling.validation import ValidationError, validate_decision
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


def _is_discovery_row(row: RunJob) -> bool:
    outcome = row.outcome_json or {}
    return (
        row.stage is RunJobStage.DEDUPLICATED
        and row.status is RunJobStatus.SUCCEEDED
        and outcome.get("acquisition") == "discovery"
    )


def collect_candidates(session: Session, run_id: str) -> tuple[FeedbackCandidate, ...]:
    """Devuelve los candidatos de discovery del run en orden determinista."""

    rows = session.execute(
        select(RunJob, Job)
        .join(Job, Job.id == RunJob.job_id)
        .where(RunJob.run_id == run_id)
        .order_by(RunJob.job_id)
    ).all()
    candidates: list[FeedbackCandidate] = []
    seen: set[str] = set()
    for run_job, job in rows:
        if not _is_discovery_row(run_job) or job.id in seen:
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


def build_surface(session: Session, run_id: str) -> FeedbackSurface:
    """Ensambla la superficie ordenada con relevancia recomputada del snapshot."""

    run = session.get(JobSearchRun, run_id)
    if run is None:
        raise LookupError("run not found")
    cycle = DiscoveryRepository(session).get_cycle_for_run(run_id)
    approved = _approved_phrases(session, run_id)
    candidates = collect_candidates(session, run_id)
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
    )


def render_candidate(candidate: FeedbackCandidate, *, index: int, total: int) -> str:
    """Compone un candidato con display v2 sin tocar la CLI histórica."""

    rendered = render_pilot_item(
        PilotItem(
            opaque_id=candidate.job_id,
            title=candidate.title,
            company=candidate.company,
            location=candidate.location,
            description=candidate.description,
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
    expected_revision: int | None = None,
) -> tuple[Any, bool]:
    """Valida con el contrato blind y anexa una revisión idempotente."""

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
    surface = build_surface(session, run_id)
    bands = {item.job_id: item.band for item in surface.items}
    if job_id not in bands:
        raise LookupError("feedback job not in run")
    return FeedbackRepository(session).submit(
        run_id=run_id,
        job_id=job_id,
        label=decision.label.value,
        primary_reason=decision.primary_reason,
        secondary_reasons=decision.secondary_reasons,
        note=decision.note,
        relevance_band=bands[job_id],
        policy_version=surface.policy_version,
        expected_revision=expected_revision,
    )


def summarize(session: Session, run_id: str) -> dict[str, Any]:
    """Resume decisiones y bandas sin exponer texto de ofertas."""

    surface = build_surface(session, run_id)
    base = FeedbackRepository(session).summary(run_id)
    bands: dict[str, int] = {}
    for item in surface.items:
        if item.decision is not None:
            key = item.band or "unranked"
            bands[key] = bands.get(key, 0) + 1
    return {
        **base,
        "cycle_id": surface.cycle_id,
        "planner_version": surface.planner_version,
        "policy_version": surface.policy_version,
        "candidates": len(surface.items),
        "unrelated_count": surface.unrelated_count,
        "excluded_count": surface.excluded_count,
        "decided_bands": bands,
    }
