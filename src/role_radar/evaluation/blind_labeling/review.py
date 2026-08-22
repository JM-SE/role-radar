"""Deterministic, score-blind pilot review planning."""
# ruff: noqa: E501

from __future__ import annotations

from role_radar.evaluation.blind_labeling.contracts import (
    Decision,
    PilotSnapshot,
    ReviewItem,
    ReviewPlan,
)
from role_radar.evaluation.blind_labeling.policy import (
    DOMAIN_REVIEW_ORDER,
    DOMAIN_REVIEW_PLAN,
    DOMAIN_REVIEW_SAMPLE,
    PROFILE_ID,
    PROFILE_SCHEMA,
    PROFILE_SHA256,
    PROFILE_VERSION,
    PROTOCOL_VERSION,
    REVIEW_NON_MAYBE_LIMIT,
    RUBRIC_VERSION,
    semantic_hash,
)
from role_radar.evaluation.blind_labeling.validation import decision_dict


def first_pass_hash(snapshot: PilotSnapshot, decisions: dict[str, Decision]) -> str:
    values = [
        {"opaque_id": item.opaque_id, "decision": decision_dict(decisions[item.opaque_id])}
        for item in sorted(snapshot.items, key=lambda value: value.opaque_id)
    ]
    return semantic_hash(
        "f10.2:first-pass-v1",
        {"dataset_id": snapshot.dataset_id, "pilot_sha256": snapshot.pilot_sha256, "items": values},
    )


def build_review_plan(
    snapshot: PilotSnapshot,
    decisions: dict[str, Decision],
    *,
    generation: int,
    rubric_sha256: str,
) -> ReviewPlan:
    first_hash = first_pass_hash(snapshot, decisions)
    maybe_ids = {item_id for item_id, decision in decisions.items() if decision.label.value == "maybe"}
    candidates = [item for item in snapshot.items if item.opaque_id not in maybe_ids]
    sampled = sorted(
        (
            semantic_hash(
                DOMAIN_REVIEW_SAMPLE,
                {
                    "dataset_id": snapshot.dataset_id,
                    "pilot_sha256": snapshot.pilot_sha256,
                    "pilot_view_sha256": snapshot.pilot_view_sha256,
                    "profile": [PROFILE_ID, PROFILE_VERSION, PROFILE_SCHEMA, PROFILE_SHA256],
                    "protocol": PROTOCOL_VERSION,
                    "rubric": [RUBRIC_VERSION, rubric_sha256],
                    "opaque_id": item.opaque_id,
                },
            ),
            item.opaque_id,
        )
        for item in candidates
    )[:REVIEW_NON_MAYBE_LIMIT]
    member_ids = set(maybe_ids) | {item_id for _digest, item_id in sampled}
    ordered = tuple(
        item_id
        for _digest, item_id in sorted(
            (
                semantic_hash(DOMAIN_REVIEW_ORDER, {"generation": generation, "opaque_id": item_id}),
                item_id,
            )
            for item_id in member_ids
        )
    )
    plan_hash = semantic_hash(
        DOMAIN_REVIEW_PLAN,
        {
            "schema": "f10.2-review-plan-v1",
            "generation": generation,
            "first_pass_sha256": first_hash,
            "item_ids": ordered,
            "protocol": PROTOCOL_VERSION,
            "rubric_sha256": rubric_sha256,
        },
    )
    return ReviewPlan(generation, first_hash, ordered, plan_hash)


def review_items(snapshot: PilotSnapshot, plan: ReviewPlan) -> tuple[ReviewItem, ...]:
    by_id = {item.opaque_id: item for item in snapshot.items}
    return tuple(
        ReviewItem(index=index, total=len(plan.item_ids), item=by_id[item_id])
        for index, item_id in enumerate(plan.item_ids, start=1)
    )


__all__ = ["build_review_plan", "first_pass_hash", "review_items"]
