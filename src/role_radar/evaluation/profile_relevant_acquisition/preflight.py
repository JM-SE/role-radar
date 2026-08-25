"""Offline preflight seam for provenance and binding validation."""

from role_radar.evaluation.profile_relevant_acquisition.provenance import (
    ProvenanceBundle,
    ProvenanceError,
    validate_provenance,
)


def validate_preflight(bundle: ProvenanceBundle) -> None:
    """Validate immutable pre-gate inputs without network or persistence."""

    validate_provenance(bundle)


__all__ = ["ProvenanceBundle", "ProvenanceError", "validate_preflight", "validate_provenance"]
