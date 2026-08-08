"""Collectors asíncronos de fuentes externas."""

from role_radar.collectors.greenhouse import GreenhouseCollector
from role_radar.collectors.lever import LeverCollector
from role_radar.collectors.outcomes import CollectionOutcome, CollectorFailureCode
from role_radar.collectors.protocols import CollectionContext, JobCollector

__all__ = [
    "CollectionContext",
    "CollectionOutcome",
    "CollectorFailureCode",
    "GreenhouseCollector",
    "JobCollector",
    "LeverCollector",
]
