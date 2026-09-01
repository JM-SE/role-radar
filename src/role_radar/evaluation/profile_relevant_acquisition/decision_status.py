"""Explicit projection of the preserved stale preregistration decision."""

from __future__ import annotations

from role_radar.evaluation.profile_relevant_acquisition.contracts import DecisionStatus

HISTORICAL_PREREGISTRATION_STATUS = DecisionStatus(
    status="non_executable",
    executable=False,
    reason="historical_preregistration_stale_bindings",
)


def historical_preregistration_status() -> DecisionStatus:
    """Return the immutable status projection; never return its values as defaults."""

    return HISTORICAL_PREREGISTRATION_STATUS


__all__ = ["HISTORICAL_PREREGISTRATION_STATUS", "historical_preregistration_status"]
