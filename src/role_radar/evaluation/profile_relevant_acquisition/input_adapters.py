"""Typed input adapters; canonical observation mapping has one owner."""

from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    AcquisitionError,
    ObservationEnvelope,
    canonical_observation_from_raw,
)

__all__ = ["AcquisitionError", "ObservationEnvelope", "canonical_observation_from_raw"]
