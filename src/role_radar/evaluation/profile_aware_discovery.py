"""Thin evaluation consumer for the shared profile-aware discovery plan.

Evaluation receives an already compiled and hashed v2 plan.  It does not own
profile terms, provider hosts, query syntax, authorization, or a second
planner, and it has no product Source/Job registration seam.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from role_radar.continuous_acquisition.runtime_discovery_v2 import verify_plan
from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2


class ProfileAwareDiscoveryError(ValueError):
    """Sanitized failure from the evaluation-consumption boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProfileAwareDiscoveryInput:
    """The verified plan identity handed to a future evaluation runner."""

    plan: DiscoveryQueryPlanV2

    @property
    def plan_sha256(self) -> str:
        return self.plan.plan_sha256

    @property
    def profile_binding(self) -> object:
        return self.plan.profile_binding

    @property
    def queries(self) -> tuple[object, ...]:
        return self.plan.queries

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "profile-aware-discovery-input-v1",
            "plan_schema_version": self.plan.schema_version,
            "planner_version": self.plan.planner_version,
            "compiler_version": self.plan.compiler_version,
            "profile_id": self.plan.profile_binding.profile_id,
            "profile_version": self.plan.profile_binding.row_version,
            "profile_schema_version": self.plan.profile_binding.schema_version,
            "profile_sha256": self.plan.profile_binding.canonical_profile_sha256,
            "policy_version": self.plan.policy_version,
            "policy_sha256": self.plan.policy_sha256,
            "plan_sha256": self.plan.plan_sha256,
            "query_count": len(self.plan.queries),
        }


def consume_discovery_plan(
    plan: DiscoveryQueryPlanV2,
    *,
    expected_plan_sha256: str | None = None,
    expected_profile_binding: object | None = None,
    sink: Callable[[ProfileAwareDiscoveryInput], Any] | None = None,
) -> ProfileAwareDiscoveryInput:
    """Verify and expose the same immutable plan to an evaluation sink."""

    try:
        verified = verify_plan(plan)
    except (TypeError, ValueError) as exc:
        raise ProfileAwareDiscoveryError(getattr(exc, "code", "discovery_plan_invalid")) from exc
    if expected_plan_sha256 is not None and verified.plan_sha256 != expected_plan_sha256:
        raise ProfileAwareDiscoveryError("discovery_plan_binding_mismatch")
    if (
        expected_profile_binding is not None
        and verified.profile_binding != expected_profile_binding
    ):
        raise ProfileAwareDiscoveryError("discovery_profile_binding_mismatch")
    value = ProfileAwareDiscoveryInput(verified)
    if sink is not None:
        try:
            sink(value)
        except Exception as exc:
            raise ProfileAwareDiscoveryError("evaluation_sink_failed") from exc
    return value


def verify_discovery_plan(plan: DiscoveryQueryPlanV2) -> DiscoveryQueryPlanV2:
    """Small named seam for callers that only need plan verification."""

    return consume_discovery_plan(plan).plan


# Names used by future evaluation code should remain explicit about consuming
# an existing plan; none of them constructs a plan or registers product data.
ProfileAwareDiscoveryPlan = ProfileAwareDiscoveryInput
consume_verified_plan = consume_discovery_plan
verify_plan_for_evaluation = verify_discovery_plan


__all__ = [
    "ProfileAwareDiscoveryError",
    "ProfileAwareDiscoveryInput",
    "ProfileAwareDiscoveryPlan",
    "consume_discovery_plan",
    "consume_verified_plan",
    "verify_discovery_plan",
    "verify_plan_for_evaluation",
]
