"""Pure final label bundle construction and semantic identity."""
# ruff: noqa: E501

from __future__ import annotations

from typing import Any

from role_radar.evaluation.blind_labeling.contracts import AuditKind, PilotSnapshot, SessionState
from role_radar.evaluation.blind_labeling.policy import (
    ALEMBIC_HEAD,
    CODE_COMMIT,
    CORPUS_SHA256,
    DATASET_ID,
    EXTERNAL_MANIFEST_SCHEMA,
    HOLDOUT_SHA256,
    INTERNAL_MANIFEST_SCHEMA,
    LABEL_DEFINITIONS,
    LABEL_DOMAINS,
    LABELSET_ID_SCHEMA,
    PILOT_COUNT,
    PILOT_FILE_SHA256,
    PILOT_SHA256,
    PROFILE_ID,
    PROFILE_SCHEMA,
    PROFILE_SHA256,
    PROFILE_VERSION,
    PROTOCOL_VERSION,
    RUBRIC_SCHEMA,
    RUBRIC_VERSION,
    semantic_hash,
)
from role_radar.evaluation.blind_labeling.session import final_decisions
from role_radar.evaluation.blind_labeling.validation import canonical_line, decision_dict


def rubric_payload() -> dict[str, Any]:
    return {
        "schema_version": RUBRIC_SCHEMA,
        "version": RUBRIC_VERSION,
        "protocol": PROTOCOL_VERSION,
        "definitions": dict(LABEL_DEFINITIONS),
        "reasons": {key: list(value) for key, value in LABEL_DOMAINS.items()},
        "notes": {"max_codepoints": 280, "maybe_optional": True, "other_required": True},
    }


def rubric_hash() -> str:
    return semantic_hash("f10.2:rubric-v1", rubric_payload())


def _audit_semantics(state: SessionState) -> list[dict[str, Any]]:
    return [
        {
            "kind": event.kind.value,
            "phase": event.phase.value,
            "generation": event.generation,
            "item_id": event.item_id,
            "before": event.before,
            "after": event.after,
        }
        for event in state.audit_events
        if event.kind is not AuditKind.FINALIZED
    ]


def build_bundle(snapshot: PilotSnapshot, state: SessionState, finalized_at: str) -> tuple[dict[str, bytes], dict[str, Any], str]:
    decisions = final_decisions(state)
    labels = [
        {"opaque_id": item.opaque_id, "decision": decision_dict(decisions[item.opaque_id])}
        for item in sorted(snapshot.items, key=lambda value: value.opaque_id)
    ]
    labels_hash = semantic_hash("f10.2:final-labels-v1", labels)
    review = {
        "schema_version": "f10.2-review-report-v1",
        "review_plan_sha256": state.review_plan.plan_sha256 if state.review_plan else None,
        "reviewed_count": len(state.review_decisions),
        "matched_count": sum(1 for value in state.review_decisions if value.matches_first_pass),
        "discrepant_count": sum(1 for value in state.review_decisions if not value.matches_first_pass),
        "adjudicated_count": len(state.adjudications),
        "consistency": "descriptive_only",
    }
    review_hash = semantic_hash("f10.2:review-report-v1", review)
    audit_hash = semantic_hash("f10.2:audit-v1", _audit_semantics(state))
    rubric = rubric_payload()
    rubric_sha = rubric_hash()
    preimage = {
        "schema": LABELSET_ID_SCHEMA,
        "dataset_id": DATASET_ID,
        "corpus_sha256": CORPUS_SHA256,
        "pilot_sha256": PILOT_SHA256,
        "pilot_view_sha256": PILOT_FILE_SHA256,
        "holdout_sha256": HOLDOUT_SHA256,
        "profile": [PROFILE_ID, PROFILE_VERSION, PROFILE_SCHEMA, PROFILE_SHA256],
        "protocol": PROTOCOL_VERSION,
        "rubric": [RUBRIC_VERSION, rubric_sha],
        "labels_sha256": labels_hash,
        "review_sha256": review_hash,
        "audit_sha256": audit_hash,
    }
    labelset_id = semantic_hash("f10.2:labelset-id-v1", preimage)
    internal = {
        "schema_version": INTERNAL_MANIFEST_SCHEMA,
        "dataset_id": DATASET_ID,
        "labelset_id": labelset_id,
        "counts": {"total": PILOT_COUNT, "reviewed": len(state.review_decisions), "adjudicated": len(state.adjudications)},
        "frozen": {"corpus_sha256": CORPUS_SHA256, "pilot_sha256": PILOT_SHA256, "pilot_view_sha256": PILOT_FILE_SHA256, "holdout_sha256": HOLDOUT_SHA256},
        "profile": {"id": PROFILE_ID, "version": PROFILE_VERSION, "schema": PROFILE_SCHEMA, "sha256": PROFILE_SHA256},
        "protocol": PROTOCOL_VERSION,
        "rubric": {"version": RUBRIC_VERSION, "sha256": rubric_sha},
        "semantic_hashes": {"labels": labels_hash, "review": review_hash, "audit": audit_hash},
        "alembic_head": ALEMBIC_HEAD,
        "code_commit": CODE_COMMIT,
        "finalized_at": finalized_at,
        "preimage": preimage,
    }
    audit_events = tuple(
        event for event in state.audit_events if event.kind is not AuditKind.FINALIZED
    )
    payloads = {
        "labels.jsonl": b"".join(canonical_line(value) for value in labels),
        "audit.jsonl": b"".join(
            canonical_line({**value, "revision": event.revision, "occurred_at": event.occurred_at})
            for event, value in zip(audit_events, _audit_semantics(state), strict=True)
        ),
        "review-report.json": canonical_line(review),
        "rubric.json": canonical_line(rubric),
        "internal-manifest.json": canonical_line(internal),
    }
    return payloads, internal, labelset_id


def external_manifest(internal: dict[str, Any], file_hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": EXTERNAL_MANIFEST_SCHEMA,
        "status": "finalized",
        "dataset_id": internal["dataset_id"],
        "labelset_id": internal["labelset_id"],
        "count": PILOT_COUNT,
        "reviewed_count": internal["counts"]["reviewed"],
        "adjudicated_count": internal["counts"]["adjudicated"],
        "frozen": internal["frozen"],
        "profile": internal["profile"],
        "protocol": internal["protocol"],
        "rubric": internal["rubric"],
        "file_hashes": file_hashes,
        "finalized_at": internal["finalized_at"],
    }


__all__ = ["build_bundle", "external_manifest", "rubric_hash", "rubric_payload"]
