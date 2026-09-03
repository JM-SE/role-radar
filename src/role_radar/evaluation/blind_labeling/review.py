"""Deterministic, score-blind pilot review planning."""

from __future__ import annotations

from typing import Protocol

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


class ReviewPlanBinding(Protocol):
    """Identity fields used to derive a review plan.

    The protocol keeps review planning independent from the materialization
    layer while allowing R3 to provide its already-validated active binding.
    """

    dataset_id: str
    pilot_sha256: str
    pilot_view_sha256: str
    profile_id: str
    profile_version: int
    profile_schema: int
    profile_sha256: str
    rubric_version: str
    rubric_sha256: str
    protocol_version: str


def _legacy_review_binding() -> ReviewPlanBinding:
    class LegacyBinding:
        dataset_id = ""
        pilot_sha256 = ""
        pilot_view_sha256 = ""
        profile_id = PROFILE_ID
        profile_version = PROFILE_VERSION
        profile_schema = PROFILE_SCHEMA
        profile_sha256 = PROFILE_SHA256
        rubric_version = RUBRIC_VERSION
        rubric_sha256 = ""
        protocol_version = PROTOCOL_VERSION

    return LegacyBinding()


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
    active_binding: ReviewPlanBinding | None = None,
) -> ReviewPlan:
    binding = active_binding or _legacy_review_binding()
    dataset_id = binding.dataset_id or snapshot.dataset_id
    pilot_sha256 = binding.pilot_sha256 or snapshot.pilot_sha256
    pilot_view_sha256 = binding.pilot_view_sha256 or snapshot.pilot_view_sha256
    effective_rubric_sha256 = binding.rubric_sha256 or rubric_sha256
    first_hash = first_pass_hash(snapshot, decisions)
    maybe_ids = {
        item_id for item_id, decision in decisions.items() if decision.label.value == "maybe"
    }
    candidates = [item for item in snapshot.items if item.opaque_id not in maybe_ids]
    sampled = sorted(
        (
            semantic_hash(
                DOMAIN_REVIEW_SAMPLE,
                {
                    "dataset_id": dataset_id,
                    "pilot_sha256": pilot_sha256,
                    "pilot_view_sha256": pilot_view_sha256,
                    "profile": [
                        binding.profile_id,
                        binding.profile_version,
                        binding.profile_schema,
                        binding.profile_sha256,
                    ],
                    "protocol": binding.protocol_version,
                    "rubric": [binding.rubric_version, effective_rubric_sha256],
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
                semantic_hash(
                    DOMAIN_REVIEW_ORDER, {"generation": generation, "opaque_id": item_id}
                ),
                item_id,
            )
            for item_id in member_ids
        )
    )
    plan_preimage: dict[str, object] = {
        "schema": "f10.2-review-plan-v1",
        "generation": generation,
        "first_pass_sha256": first_hash,
        "item_ids": ordered,
        "protocol": binding.protocol_version,
        "rubric_sha256": effective_rubric_sha256,
    }
    # Keep the F10.2 preimage byte-for-byte stable unless an active binding is
    # explicitly supplied. R3 must bind the complete active R2 identity.
    if active_binding is not None:
        plan_preimage.update(
            {
                "dataset_id": dataset_id,
                "pilot_sha256": pilot_sha256,
                "pilot_view_sha256": pilot_view_sha256,
                "profile": [
                    binding.profile_id,
                    binding.profile_version,
                    binding.profile_schema,
                    binding.profile_sha256,
                ],
                "rubric": [binding.rubric_version, effective_rubric_sha256],
            }
        )
    plan_hash = semantic_hash(DOMAIN_REVIEW_PLAN, plan_preimage)
    return ReviewPlan(generation, first_hash, ordered, plan_hash)


def review_items(snapshot: PilotSnapshot, plan: ReviewPlan) -> tuple[ReviewItem, ...]:
    by_id = {item.opaque_id: item for item in snapshot.items}
    return tuple(
        ReviewItem(index=index, total=len(plan.item_ids), item=by_id[item_id])
        for index, item_id in enumerate(plan.item_ids, start=1)
    )


__all__ = ["build_review_plan", "first_pass_hash", "review_items"]
