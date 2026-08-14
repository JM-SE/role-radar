"""Offline-first continuous source acquisition bounded context.

This package deliberately has no dependency on the historical pipeline.  The
public seams are contracts and pure policy; provider adapters and persistence
are injected by the orchestration layers.
"""

from role_radar.continuous_acquisition.contracts import (
    ACQUISITION_POLICY_VERSION,
    FRESHNESS_POLICY_VERSION,
    IDENTITY_POLICY_VERSION,
    AcquisitionRunState,
    JobCounters,
)

__all__ = [
    "ACQUISITION_POLICY_VERSION",
    "FRESHNESS_POLICY_VERSION",
    "IDENTITY_POLICY_VERSION",
    "AcquisitionRunState",
    "JobCounters",
]
