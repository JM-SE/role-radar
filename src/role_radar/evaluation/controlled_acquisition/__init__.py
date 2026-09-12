"""Offline-safe contracts and policies for the F10.1 acquisition freeze.

This package intentionally has no dependency on the worker, normal pipeline,
LLM providers, or persistence writers.  Live orchestration is supplied through
injected adapters only after the separate Gate B approval.
"""

from importlib import import_module

_LAZY_EXPORTS = {
    "ConfigurationError": ("configuration", "ConfigurationError"),
    "ControlledAcquisitionConfig": ("configuration", "ControlledAcquisitionConfig"),
    "DatasetResult": ("contracts", "DatasetResult"),
    "Observation": ("contracts", "Observation"),
    "OperationState": ("contracts", "OperationState"),
}


def __getattr__(name: str) -> object:
    try:
        module_name, attribute = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    value = getattr(import_module(f"{__name__}.{module_name}"), attribute)
    globals()[name] = value
    return value


__all__ = [
    "ConfigurationError",
    "ControlledAcquisitionConfig",
    "DatasetResult",
    "Observation",
    "OperationState",
]
