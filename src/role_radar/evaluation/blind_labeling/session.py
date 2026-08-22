"""Pure F10.2 session state machine."""
# ruff: noqa: E501

from __future__ import annotations

from dataclasses import replace

from role_radar.evaluation.blind_labeling.contracts import (
    Adjudication,
    AuditEvent,
    AuditKind,
    Decision,
    PilotSnapshot,
    ReviewDecision,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.review import build_review_plan, first_pass_hash
from role_radar.evaluation.blind_labeling.validation import ValidationError, validate_decision


class SessionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def new_session(snapshot: PilotSnapshot, rubric_version: str, rubric_sha256: str, protocol: str, occurred_at: str) -> SessionState:
    state = SessionState(
        snapshot.dataset_id, snapshot.pilot_sha256, snapshot.pilot_view_sha256,
        rubric_version, rubric_sha256, protocol, 0, SessionPhase.LABELING, (), None,
        0, None, (), (), (),
    )
    return _event(state, AuditKind.STARTED, occurred_at, None, None, None)


def _event(
    state: SessionState,
    kind: AuditKind,
    occurred_at: str,
    item_id: str | None,
    before: dict[str, object] | None,
    after: dict[str, object] | None,
) -> SessionState:
    revision = state.revision + 1
    event = AuditEvent(revision, kind, state.phase, state.generation, item_id, before, after, occurred_at)
    return replace(state, revision=revision, audit_events=(*state.audit_events, event))


def _decisions(state: SessionState) -> dict[str, Decision]:
    return dict(state.first_pass)


def _require_revision(state: SessionState, expected_revision: int | None) -> None:
    if expected_revision is not None and state.revision != expected_revision:
        raise SessionError("stale_revision")


def save_first_pass(
    state: SessionState,
    item_id: str,
    decision: Decision,
    occurred_at: str,
    *,
    expected_revision: int | None = None,
) -> SessionState:
    _require_revision(state, expected_revision)
    if state.phase not in {SessionPhase.LABELING, SessionPhase.FIRST_PASS_COMPLETE}:
        raise SessionError("first_pass_sealed")
    try:
        decision = validate_decision(decision)
    except ValidationError as exc:
        raise SessionError(exc.code) from exc
    values = _decisions(state)
    before = values.get(item_id)
    values[item_id] = decision
    phase = SessionPhase.FIRST_PASS_COMPLETE if len(values) == 50 else SessionPhase.LABELING
    next_state = replace(state, phase=phase, first_pass=tuple(sorted(values.items())))
    return _event(
        next_state,
        AuditKind.LABEL_SAVED,
        occurred_at,
        item_id,
        _decision_payload(before),
        _decision_payload(decision),
    )


def _decision_payload(value: Decision | None) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "label": value.label.value,
        "primary_reason": value.primary_reason,
        "secondary_reasons": list(value.secondary_reasons),
        "note": value.note,
    }


def seal_for_review(state: SessionState, snapshot: PilotSnapshot, occurred_at: str) -> SessionState:
    if state.phase not in {SessionPhase.FIRST_PASS_COMPLETE, SessionPhase.REVIEWING} or len(state.first_pass) != 50:
        raise SessionError("first_pass_incomplete")
    decisions = _decisions(state)
    plan = state.review_plan or build_review_plan(snapshot, decisions, generation=state.generation, rubric_sha256=state.rubric_sha256)
    if state.review_plan is not None:
        return state
    next_state = replace(
        state,
        phase=SessionPhase.REVIEWING,
        first_pass_sha256=first_pass_hash(snapshot, decisions),
        review_plan=plan,
    )
    return _event(next_state, AuditKind.FIRST_PASS_SEALED, occurred_at, None, None, {"plan_sha256": plan.plan_sha256})


def save_review(
    state: SessionState,
    item_id: str,
    decision: Decision,
    occurred_at: str,
    *,
    expected_revision: int | None = None,
) -> SessionState:
    _require_revision(state, expected_revision)
    if state.phase not in {SessionPhase.REVIEWING, SessionPhase.ADJUDICATION_PENDING, SessionPhase.READY_TO_FINALIZE} or state.review_plan is None:
        raise SessionError("review_not_open")
    if item_id not in state.review_plan.item_ids:
        raise SessionError("review_item_invalid")
    if any(value.item_id == item_id for value in state.review_decisions):
        raise SessionError("review_already_saved")
    try:
        decision = validate_decision(decision)
    except ValidationError as exc:
        raise SessionError(exc.code) from exc
    first = _decisions(state)[item_id]
    result = ReviewDecision(item_id, decision, decision == first)
    results = (*state.review_decisions, result)
    phase = SessionPhase.REVIEWING
    if len(results) == len(state.review_plan.item_ids):
        phase = SessionPhase.READY_TO_FINALIZE if all(item.matches_first_pass for item in results) else SessionPhase.ADJUDICATION_PENDING
    next_state = replace(state, phase=phase, review_decisions=tuple(sorted(results, key=lambda value: value.item_id)))
    return _event(next_state, AuditKind.REVIEW_SAVED, occurred_at, item_id, None, {"matches": result.matches_first_pass})


def unresolved_items(state: SessionState) -> tuple[str, ...]:
    return tuple(item.item_id for item in state.review_decisions if not item.matches_first_pass and not any(value.item_id == item.item_id for value in state.adjudications))


def adjudicate(state: SessionState, item_id: str, decision: Decision, occurred_at: str, *, expected_revision: int | None = None) -> SessionState:
    _require_revision(state, expected_revision)
    if state.phase is not SessionPhase.ADJUDICATION_PENDING or item_id not in unresolved_items(state):
        raise SessionError("adjudication_invalid")
    try:
        decision = validate_decision(decision)
    except ValidationError as exc:
        raise SessionError(exc.code) from exc
    values = (*state.adjudications, Adjudication(item_id, decision))
    phase = SessionPhase.READY_TO_FINALIZE if not unresolved_items(replace(state, adjudications=values)) else SessionPhase.ADJUDICATION_PENDING
    next_state = replace(state, phase=phase, adjudications=tuple(sorted(values, key=lambda value: value.item_id)))
    return _event(next_state, AuditKind.ADJUDICATED, occurred_at, item_id, None, _decision_payload(decision))


def reopen(state: SessionState, occurred_at: str, *, expected_revision: int | None = None) -> SessionState:
    _require_revision(state, expected_revision)
    if state.phase in {SessionPhase.FINALIZED, SessionPhase.LABELING, SessionPhase.FIRST_PASS_COMPLETE}:
        raise SessionError("reopen_invalid")
    next_state = replace(
        state, phase=SessionPhase.LABELING if len(state.first_pass) < 50 else SessionPhase.FIRST_PASS_COMPLETE,
        first_pass_sha256=None, generation=state.generation + 1, review_plan=None,
        review_decisions=(), adjudications=(), finalization_intent=None,
    )
    return _event(next_state, AuditKind.REOPENED, occurred_at, None, None, {"generation": next_state.generation})


def final_decisions(state: SessionState) -> dict[str, Decision]:
    if state.phase not in {SessionPhase.READY_TO_FINALIZE, SessionPhase.FINALIZED}:
        raise SessionError("not_ready_to_finalize")
    result = _decisions(state)
    reviews = {item.item_id: item for item in state.review_decisions}
    adjudications = {item.item_id: item.decision for item in state.adjudications}
    for item_id, review in reviews.items():
        result[item_id] = adjudications.get(item_id, review.decision)
    if len(result) != 50:
        raise SessionError("label_cardinality_invalid")
    return result


def mark_finalized(state: SessionState, occurred_at: str) -> SessionState:
    if state.phase is not SessionPhase.READY_TO_FINALIZE:
        raise SessionError("not_ready_to_finalize")
    return _event(replace(state, phase=SessionPhase.FINALIZED), AuditKind.FINALIZED, occurred_at, None, None, None)


__all__ = [
    "SessionError",
    "adjudicate",
    "final_decisions",
    "mark_finalized",
    "new_session",
    "reopen",
    "save_first_pass",
    "save_review",
    "seal_for_review",
    "unresolved_items",
]
