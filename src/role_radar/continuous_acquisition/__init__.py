"""Offline-first continuous source acquisition bounded context.

This package deliberately has no dependency on the historical pipeline.  The
public seams are contracts and pure policy; provider adapters and persistence
are injected by the orchestration layers.
"""

__all__ = [
    "ACQUISITION_POLICY_VERSION",
    "FRESHNESS_POLICY_VERSION",
    "IDENTITY_POLICY_VERSION",
    "AcquisitionRunState",
    "JobCounters",
]


def __getattr__(name: str) -> object:
    """Resolve compatibility exports without importing collector adapters."""

    if name in {
        "ACQUISITION_POLICY_VERSION",
        "FRESHNESS_POLICY_VERSION",
        "IDENTITY_POLICY_VERSION",
        "AcquisitionRunState",
        "JobCounters",
    }:
        from role_radar.continuous_acquisition import contracts

        return getattr(contracts, name)
    raise AttributeError(name)
