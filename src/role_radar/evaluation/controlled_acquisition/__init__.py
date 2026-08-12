"""Offline-safe contracts and policies for the F10.1 acquisition freeze.

This package intentionally has no dependency on the worker, normal pipeline,
LLM providers, or persistence writers.  Live orchestration is supplied through
injected adapters only after the separate Gate B approval.
"""

from role_radar.evaluation.controlled_acquisition.configuration import (
    ConfigurationError,
    ControlledAcquisitionConfig,
)
from role_radar.evaluation.controlled_acquisition.contracts import (
    DatasetResult,
    Observation,
    OperationState,
)

__all__ = [
    "ConfigurationError",
    "ControlledAcquisitionConfig",
    "DatasetResult",
    "Observation",
    "OperationState",
]
