"""Pure F10.2 session state machine."""

from __future__ import annotations

from dataclasses import replace

from role_radar.evaluation.blind_labeling.contracts import (
    Adjudication,
    AuditEvent,
    AuditKind,
    Decision,
    FinalizationIntent,
    PilotSnapshot,
    ReviewDecision,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.policy import (
    DATASET_ID,
    HEX64,
    OPAQUE_ID,
    current_pilot_count,
    current_protocol_version,
)
from role_radar.evaluation.blind_labeling.review import (
    ReviewPlanBinding,
    build_review_plan,
    first_pass_hash,
)
from role_radar.evaluation.blind_labeling.validation import ValidationError, validate_decision


class SessionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_state(
    state: SessionState,
    *,
    expected_dataset_id: str | None = None,
    expected_rubric_version: str | None = None,
    expected_protocol_version: str | None = None,
) -> None:
    if not isinstance(state, SessionState):
        raise SessionError("draft_state_invalid")
    if expected_dataset_id is not None and state.dataset_id != expected_dataset_id:
        raise SessionError("draft_binding_invalid")
    if (
        state.dataset_id != DATASET_ID
        and expected_dataset_id is None
        and HEX64.fullmatch(state.dataset_id) is None
    ):
        raise SessionError("draft_binding_invalid")
    for value in (state.pilot_sha256, state.pilot_view_sha256, state.rubric_sha256):
        if not isinstance(value, str) or HEX64.fullmatch(value) is None:
            raise SessionError("draft_binding_invalid")
    if expected_rubric_version is not None and state.rubric_version != expected_rubric_version:
        raise SessionError("draft_binding_invalid")
    if not isinstance(state.rubric_version, str) or not state.rubric_version:
        raise SessionError("draft_binding_invalid")
    if state.protocol_version != (expected_protocol_version or current_protocol_version()):
        raise SessionError("draft_binding_invalid")
    if (
        type(state.revision) is not int
        or type(state.generation) is not int
        or state.revision < 1
        or len(state.audit_events) != state.revision
    ):
        raise SessionError("draft_state_invalid")
    if [event.revision for event in state.audit_events] != list(range(1, state.revision + 1)):
        raise SessionError("draft_audit_invalid")
    if any(
        type(event.revision) is not int
        or type(event.generation) is not int
        or not isinstance(event.item_id, str | None)
        or not isinstance(event.before, dict | None)
        or not isinstance(event.after, dict | None)
        or not isinstance(event.occurred_at, str)
        for event in state.audit_events
    ):
        raise SessionError("draft_audit_invalid")
    if state.generation < 0:
        raise SessionError("draft_state_invalid")

    first_pass_ids = [item_id for item_id, _decision in state.first_pass]
    if first_pass_ids != sorted(first_pass_ids) or len(set(first_pass_ids)) != len(first_pass_ids):
        raise SessionError("draft_first_pass_invalid")
    if len(first_pass_ids) > current_pilot_count() or any(
        OPAQUE_ID.fullmatch(item_id) is None for item_id in first_pass_ids
    ):
        raise SessionError("draft_first_pass_invalid")
    decisions = _decisions(state)
    for decision in decisions.values():
        try:
            validate_decision(decision)
        except ValidationError as exc:
            raise SessionError("draft_decision_invalid") from exc

    plan = state.review_plan
    if plan is not None:
        if (
            type(plan.generation) is not int
            or not isinstance(plan.first_pass_sha256, str)
            or not isinstance(plan.plan_sha256, str)
            or plan.generation != state.generation
            or HEX64.fullmatch(plan.first_pass_sha256) is None
            or HEX64.fullmatch(plan.plan_sha256) is None
        ):
            raise SessionError("draft_review_plan_invalid")
        if not plan.item_ids or len(set(plan.item_ids)) != len(plan.item_ids):
            raise SessionError("draft_review_plan_invalid")
        if any(
            OPAQUE_ID.fullmatch(item_id) is None or item_id not in decisions
            for item_id in plan.item_ids
        ):
            raise SessionError("draft_review_plan_invalid")
    review_ids = [item.item_id for item in state.review_decisions]
    if len(set(review_ids)) != len(review_ids) or any(
        plan is None or item_id not in plan.item_ids for item_id in review_ids
    ):
        raise SessionError("draft_review_invalid")
    for item in state.review_decisions:
        if not isinstance(item.matches_first_pass, bool) or item.matches_first_pass != (
            item.decision == decisions[item.item_id]
        ):
            raise SessionError("draft_review_invalid")
        try:
            validate_decision(item.decision)
        except ValidationError as exc:
            raise SessionError("draft_review_invalid") from exc
    adjudication_ids = [item.item_id for item in state.adjudications]
    if len(set(adjudication_ids)) != len(adjudication_ids):
        raise SessionError("draft_adjudication_invalid")
    discrepancies = {item.item_id for item in state.review_decisions if not item.matches_first_pass}
    if any(item_id not in discrepancies for item_id in adjudication_ids):
        raise SessionError("draft_adjudication_invalid")
    for adjudication in state.adjudications:
        try:
            validate_decision(adjudication.decision)
        except ValidationError as exc:
            raise SessionError("draft_adjudication_invalid") from exc

    if plan is None:
        if state.phase not in {SessionPhase.LABELING, SessionPhase.FIRST_PASS_COMPLETE}:
            raise SessionError("draft_phase_invalid")
        if state.first_pass_sha256 is not None or state.review_decisions or state.adjudications:
            raise SessionError("draft_state_invalid")
    elif state.phase in {
        SessionPhase.REVIEWING,
        SessionPhase.ADJUDICATION_PENDING,
        SessionPhase.READY_TO_FINALIZE,
        SessionPhase.FINALIZED,
    }:
        if len(first_pass_ids) != current_pilot_count() or state.first_pass_sha256 is None:
            raise SessionError("draft_phase_invalid")
        if len(review_ids) > len(plan.item_ids):
            raise SessionError("draft_review_invalid")
        if state.phase is SessionPhase.REVIEWING and len(review_ids) == len(plan.item_ids):
            raise SessionError("draft_phase_invalid")
        if state.phase is SessionPhase.ADJUDICATION_PENDING and (
            len(review_ids) != len(plan.item_ids)
            or not discrepancies
            or set(adjudication_ids) >= discrepancies
        ):
            raise SessionError("draft_phase_invalid")
        if state.phase in {SessionPhase.READY_TO_FINALIZE, SessionPhase.FINALIZED} and (
            len(review_ids) != len(plan.item_ids) or discrepancies - set(adjudication_ids)
        ):
            raise SessionError("draft_phase_invalid")
    else:
        raise SessionError("draft_phase_invalid")

    intent = state.finalization_intent
    if intent is not None:
        if state.phase not in {SessionPhase.READY_TO_FINALIZE, SessionPhase.FINALIZED}:
            raise SessionError("draft_finalization_invalid")
        if (
            type(intent.draft_revision) is not int
            or intent.draft_revision >= state.revision
            or intent.draft_revision < 1
        ):
            raise SessionError("draft_finalization_invalid")
        if any(
            HEX64.fullmatch(value) is None
            for value in (
                intent.challenge_sha256,
                intent.draft_payload_sha256,
                intent.labelset_id,
                intent.final_labels_sha256,
                intent.review_report_sha256,
                intent.audit_sha256,
            )
        ):
            raise SessionError("draft_finalization_invalid")
        if not isinstance(intent.finalized_at, str) or not intent.finalized_at:
            raise SessionError("draft_finalization_invalid")
    elif state.phase is SessionPhase.FINALIZED:
        raise SessionError("draft_finalization_invalid")

    if not state.audit_events or state.audit_events[0].kind is not AuditKind.STARTED:
        raise SessionError("draft_audit_invalid")
    if any(event.generation < 0 for event in state.audit_events):
        raise SessionError("draft_audit_invalid")


def begin_finalization(
    state: SessionState, intent: FinalizationIntent, occurred_at: str
) -> SessionState:
    validate_state(state)
    if state.phase is not SessionPhase.READY_TO_FINALIZE or state.finalization_intent is not None:
        raise SessionError("finalization_invalid")
    return _event(
        replace(state, finalization_intent=intent),
        AuditKind.FINALIZATION_INTENT,
        occurred_at,
        None,
        None,
        {
            "labelset_id": intent.labelset_id,
            "challenge_sha256": intent.challenge_sha256,
        },
    )


def validate_state_against_snapshot(
    state: SessionState,
    snapshot: PilotSnapshot,
    *,
    expected_protocol_version: str | None = None,
    active_binding: ReviewPlanBinding | None = None,
) -> None:
    validate_state(
        state,
        expected_dataset_id=snapshot.dataset_id,
        expected_protocol_version=expected_protocol_version,
    )
    snapshot_ids = tuple(sorted(item.opaque_id for item in snapshot.items))
    first_pass_ids = tuple(item_id for item_id, _decision in state.first_pass)
    if len(snapshot.items) != current_pilot_count() or (
        first_pass_ids and set(first_pass_ids) - set(snapshot_ids)
    ):
        raise SessionError("draft_snapshot_mismatch")
    if (
        state.pilot_sha256 != snapshot.pilot_sha256
        or state.pilot_view_sha256 != snapshot.pilot_view_sha256
    ):
        raise SessionError("draft_snapshot_mismatch")
    if state.review_plan is not None:
        expected = build_review_plan(
            snapshot,
            dict(state.first_pass),
            generation=state.generation,
            rubric_sha256=state.rubric_sha256,
            active_binding=active_binding,
        )
        if state.first_pass_sha256 != expected.first_pass_sha256 or state.review_plan != expected:
            raise SessionError("draft_review_plan_invalid")


def new_session(
    snapshot: PilotSnapshot,
    rubric_version: str,
    rubric_sha256: str,
    protocol: str,
    occurred_at: str,
) -> SessionState:
    state = SessionState(
        snapshot.dataset_id,
        snapshot.pilot_sha256,
        snapshot.pilot_view_sha256,
        rubric_version,
        rubric_sha256,
        protocol,
        0,
        SessionPhase.LABELING,
        (),
        None,
        0,
        None,
        (),
        (),
        (),
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
    event = AuditEvent(
        revision, kind, state.phase, state.generation, item_id, before, after, occurred_at
    )
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
    allowed_item_ids: frozenset[str] | None = None,
) -> SessionState:
    _require_revision(state, expected_revision)
    if state.phase not in {SessionPhase.LABELING, SessionPhase.FIRST_PASS_COMPLETE}:
        raise SessionError("first_pass_sealed")
    if allowed_item_ids is not None and item_id not in allowed_item_ids:
        raise SessionError("pilot_item_invalid")
    try:
        decision = validate_decision(decision)
    except ValidationError as exc:
        raise SessionError(exc.code) from exc
    values = _decisions(state)
    before = values.get(item_id)
    if before is None and len(values) >= current_pilot_count():
        raise SessionError("label_cardinality_invalid")
    values[item_id] = decision
    phase = (
        SessionPhase.FIRST_PASS_COMPLETE
        if len(values) == current_pilot_count()
        else SessionPhase.LABELING
    )
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


def seal_for_review(
    state: SessionState,
    snapshot: PilotSnapshot,
    occurred_at: str,
    *,
    active_binding: ReviewPlanBinding | None = None,
) -> SessionState:
    if (
        state.phase not in {SessionPhase.FIRST_PASS_COMPLETE, SessionPhase.REVIEWING}
        or len(state.first_pass) != current_pilot_count()
    ):
        raise SessionError("first_pass_incomplete")
    decisions = _decisions(state)
    plan = state.review_plan or build_review_plan(
        snapshot,
        decisions,
        generation=state.generation,
        rubric_sha256=state.rubric_sha256,
        active_binding=active_binding,
    )
    if state.review_plan is not None:
        return state
    next_state = replace(
        state,
        phase=SessionPhase.REVIEWING,
        first_pass_sha256=first_pass_hash(snapshot, decisions),
        review_plan=plan,
    )
    return _event(
        next_state,
        AuditKind.FIRST_PASS_SEALED,
        occurred_at,
        None,
        None,
        {"plan_sha256": plan.plan_sha256},
    )


def save_review(
    state: SessionState,
    item_id: str,
    decision: Decision,
    occurred_at: str,
    *,
    expected_revision: int | None = None,
) -> SessionState:
    _require_revision(state, expected_revision)
    if (
        state.phase
        not in {
            SessionPhase.REVIEWING,
            SessionPhase.ADJUDICATION_PENDING,
            SessionPhase.READY_TO_FINALIZE,
        }
        or state.review_plan is None
    ):
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
        phase = (
            SessionPhase.READY_TO_FINALIZE
            if all(item.matches_first_pass for item in results)
            else SessionPhase.ADJUDICATION_PENDING
        )
    next_state = replace(
        state, phase=phase, review_decisions=tuple(sorted(results, key=lambda value: value.item_id))
    )
    return _event(
        next_state,
        AuditKind.REVIEW_SAVED,
        occurred_at,
        item_id,
        None,
        {"matches": result.matches_first_pass},
    )


def unresolved_items(state: SessionState) -> tuple[str, ...]:
    return tuple(
        item.item_id
        for item in state.review_decisions
        if not item.matches_first_pass
        and not any(value.item_id == item.item_id for value in state.adjudications)
    )


def adjudicate(
    state: SessionState,
    item_id: str,
    decision: Decision,
    occurred_at: str,
    *,
    expected_revision: int | None = None,
) -> SessionState:
    _require_revision(state, expected_revision)
    if state.phase is not SessionPhase.ADJUDICATION_PENDING or item_id not in unresolved_items(
        state
    ):
        raise SessionError("adjudication_invalid")
    try:
        decision = validate_decision(decision)
    except ValidationError as exc:
        raise SessionError(exc.code) from exc
    values = (*state.adjudications, Adjudication(item_id, decision))
    phase = (
        SessionPhase.READY_TO_FINALIZE
        if not unresolved_items(replace(state, adjudications=values))
        else SessionPhase.ADJUDICATION_PENDING
    )
    next_state = replace(
        state, phase=phase, adjudications=tuple(sorted(values, key=lambda value: value.item_id))
    )
    return _event(
        next_state, AuditKind.ADJUDICATED, occurred_at, item_id, None, _decision_payload(decision)
    )


def reopen(
    state: SessionState, occurred_at: str, *, expected_revision: int | None = None
) -> SessionState:
    _require_revision(state, expected_revision)
    if (
        state.phase
        in {SessionPhase.FINALIZED, SessionPhase.LABELING, SessionPhase.FIRST_PASS_COMPLETE}
        or state.finalization_intent is not None
    ):
        raise SessionError("reopen_invalid")
    next_state = replace(
        state,
        phase=SessionPhase.LABELING
        if len(state.first_pass) < current_pilot_count()
        else SessionPhase.FIRST_PASS_COMPLETE,
        first_pass_sha256=None,
        generation=state.generation + 1,
        review_plan=None,
        review_decisions=(),
        adjudications=(),
        finalization_intent=None,
    )
    return _event(
        next_state,
        AuditKind.REOPENED,
        occurred_at,
        None,
        None,
        {"generation": next_state.generation},
    )


def final_decisions(state: SessionState) -> dict[str, Decision]:
    if state.phase not in {SessionPhase.READY_TO_FINALIZE, SessionPhase.FINALIZED}:
        raise SessionError("not_ready_to_finalize")
    result = _decisions(state)
    reviews = {item.item_id: item for item in state.review_decisions}
    adjudications = {item.item_id: item.decision for item in state.adjudications}
    for item_id, review in reviews.items():
        result[item_id] = adjudications.get(item_id, review.decision)
    if len(result) != current_pilot_count():
        raise SessionError("label_cardinality_invalid")
    return result


def mark_finalized(state: SessionState, occurred_at: str) -> SessionState:
    if state.phase is not SessionPhase.READY_TO_FINALIZE:
        raise SessionError("not_ready_to_finalize")
    return _event(
        replace(state, phase=SessionPhase.FINALIZED),
        AuditKind.FINALIZED,
        occurred_at,
        None,
        None,
        None,
    )


__all__ = [
    "SessionError",
    "adjudicate",
    "begin_finalization",
    "final_decisions",
    "mark_finalized",
    "new_session",
    "reopen",
    "save_first_pass",
    "save_review",
    "seal_for_review",
    "unresolved_items",
    "validate_state",
    "validate_state_against_snapshot",
]
