"""Immutable F10.2 domain contracts; no IO or policy logic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Label(StrEnum):
    APPLY = "apply"
    MAYBE = "maybe"
    REJECT = "reject"


class SessionPhase(StrEnum):
    NOT_STARTED = "not_started"
    LABELING = "labeling"
    FIRST_PASS_COMPLETE = "first_pass_complete"
    REVIEWING = "reviewing"
    ADJUDICATION_PENDING = "adjudication_pending"
    READY_TO_FINALIZE = "ready_to_finalize"
    FINALIZED = "finalized"


class AuditKind(StrEnum):
    STARTED = "started"
    LABEL_SAVED = "label_saved"
    FIRST_PASS_SEALED = "first_pass_sealed"
    REVIEW_SAVED = "review_saved"
    ADJUDICATED = "adjudicated"
    REOPENED = "reopened"
    FINALIZATION_INTENT = "finalization_intent"
    FINALIZED = "finalized"


@dataclass(frozen=True, slots=True)
class PilotItem:
    opaque_id: str
    title: str
    company: str
    location: str | None
    description: str


@dataclass(frozen=True, slots=True)
class PilotSnapshot:
    items: tuple[PilotItem, ...]
    dataset_id: str
    pilot_sha256: str
    pilot_view_sha256: str


@dataclass(frozen=True, slots=True)
class Decision:
    label: Label
    primary_reason: str
    secondary_reasons: tuple[str, ...] = ()
    note: str | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    revision: int
    kind: AuditKind
    phase: SessionPhase
    generation: int
    item_id: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    occurred_at: str


@dataclass(frozen=True, slots=True)
class ReviewItem:
    index: int
    total: int
    item: PilotItem


@dataclass(frozen=True, slots=True)
class ReviewDecision:
    item_id: str
    decision: Decision
    matches_first_pass: bool


@dataclass(frozen=True, slots=True)
class Adjudication:
    item_id: str
    decision: Decision


@dataclass(frozen=True, slots=True)
class ReviewPlan:
    generation: int
    first_pass_sha256: str
    item_ids: tuple[str, ...]
    plan_sha256: str


@dataclass(frozen=True, slots=True)
class FinalizationIntent:
    challenge_sha256: str
    draft_revision: int
    draft_payload_sha256: str
    labelset_id: str
    final_labels_sha256: str
    review_report_sha256: str
    audit_sha256: str
    finalized_at: str


@dataclass(frozen=True, slots=True)
class SessionState:
    dataset_id: str
    pilot_sha256: str
    pilot_view_sha256: str
    rubric_version: str
    rubric_sha256: str
    protocol_version: str
    revision: int
    phase: SessionPhase
    first_pass: tuple[tuple[str, Decision], ...]
    first_pass_sha256: str | None
    generation: int
    review_plan: ReviewPlan | None
    review_decisions: tuple[ReviewDecision, ...]
    adjudications: tuple[Adjudication, ...]
    audit_events: tuple[AuditEvent, ...]
    finalization_intent: FinalizationIntent | None = None


@dataclass(frozen=True, slots=True)
class FinalizedBundle:
    labelset_id: str
    external_manifest: dict[str, Any]


__all__ = [
    "Adjudication",
    "AuditEvent",
    "AuditKind",
    "Decision",
    "FinalizationIntent",
    "FinalizedBundle",
    "Label",
    "PilotItem",
    "PilotSnapshot",
    "ReviewDecision",
    "ReviewItem",
    "ReviewPlan",
    "SessionPhase",
    "SessionState",
]
