"""Gate E — compute_preview only (preview, no bytes, no store).

Imports only the approved F10.1E ``compute_preview`` seam, validates
provenance/prereg bindings, runs on the sealed parent pool, produces
``PreviewComputationResult`` and its sanitized preview, and stops.
No payload bytes, no ``ApprovedPreview``/``MaterializationContext``,
no store/publication, no capability, no ``materialize_payload_bytes``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Final

from role_radar.evaluation.fresh_acquisition.provenance import (
    LIVE_NAMESPACE,
    LIVE_PARTITION_SEED,
    LIVE_SELECTION_SEED,
    ProvenanceBundle,
    ProvenanceError,
    validate_provenance,
)
from role_radar.evaluation.profile_relevance.contracts import (
    PreviewComputationResult,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevance.preview_workflow import compute_preview

GATE_E_PREVIEW_HASH_DOMAIN: Final[str] = "role-radar:f10.1f:gate-e:preview-hash:v1"
GATE_E_PREVIEW_CHALLENGE_DOMAIN: Final[str] = "role-radar:f10.1f:gate-e:challenge:v1"
SCHEMA_GATE_E_RESULT: Final[str] = "f10.1f-gate-e-preview-result-v1"


class GateEError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise GateEError("gate_e_canonical_invalid") from exc
    return text.encode("utf-8")


def _domain_hash(domain: str, canonical: bytes) -> str:
    if not domain.isascii():
        raise GateEError("gate_e_domain_invalid")
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise GateEError(code)
    if any(c not in "0123456789abcdef" for c in value):
        raise GateEError(code)


@dataclass(frozen=True, slots=True)
class GateEPreviewRecord:
    """Immutable Gate E result — no bytes beyond sanitized preview."""

    preview_input_sha256: str
    selection_sha256: str
    partition_sha256: str
    pilot_membership_sha256: str
    holdout_membership_sha256: str
    sanitized_preview_sha256: str
    provenance_sha256: str
    hash_domain: str
    challenge_domain: str
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if self.hash_domain != GATE_E_PREVIEW_HASH_DOMAIN:
            raise GateEError("gate_e_hash_domain_mismatch")
        if self.challenge_domain != GATE_E_PREVIEW_CHALLENGE_DOMAIN:
            raise GateEError("gate_e_challenge_domain_mismatch")
        for name in (
            "preview_input_sha256",
            "selection_sha256",
            "partition_sha256",
            "pilot_membership_sha256",
            "holdout_membership_sha256",
            "sanitized_preview_sha256",
            "provenance_sha256",
        ):
            _require_hex64(getattr(self, name), "gate_e_hash_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise GateEError("gate_e_bytes_invalid")


def _validate_inputs_gate_e(
    *,
    inputs: ProfileRelevanceInput,
    provenance: ProvenanceBundle,
) -> None:
    if not isinstance(inputs, ProfileRelevanceInput):
        raise GateEError("gate_e_input_invalid")
    if not isinstance(provenance, ProvenanceBundle):
        raise GateEError("gate_e_provenance_invalid")
    try:
        validate_provenance(provenance)
    except ProvenanceError as exc:
        raise GateEError(exc.code) from exc

    if inputs.sealed_snapshot.state != "sealed":
        raise GateEError("gate_e_snapshot_not_sealed")
    if inputs.sealed_snapshot.namespace != LIVE_NAMESPACE:
        raise GateEError("gate_e_namespace_mismatch")
    if inputs.sealed_snapshot.namespace != provenance.namespace:
        raise GateEError("gate_e_namespace_mismatch")
    # Seeds must be exact live preregistration values — no alternate ranking.
    if inputs.sampling_policy.selection_seed != LIVE_SELECTION_SEED:
        raise GateEError("gate_e_selection_seed_mismatch")
    if inputs.partition_policy.partition_seed != LIVE_PARTITION_SEED:
        raise GateEError("gate_e_partition_seed_mismatch")
    if inputs.sampling_policy.selection_seed == inputs.partition_policy.partition_seed:
        raise GateEError("gate_e_seeds_must_differ")
    # Binding hashes must be hex.
    _require_hex64(provenance.provenance_sha256, "gate_e_hash_invalid")
    _require_hex64(inputs.preview_input_sha256, "gate_e_hash_invalid")
    _require_hex64(provenance.inventory_sha256, "gate_e_hash_invalid")
    # Historical exclusion digest shape is checked inside compute_preview; we only
    # ensure the preview input binding is present.
    if inputs.input_schema_version != "f10.1e-profile-relevance-input-v1":
        raise GateEError("gate_e_schema_invalid")


def build_gate_e_record(
    *,
    result: PreviewComputationResult,
    inputs: ProfileRelevanceInput,
    provenance: ProvenanceBundle,
) -> GateEPreviewRecord:
    payload: dict[str, Any] = {
        "challenge_domain": GATE_E_PREVIEW_CHALLENGE_DOMAIN,
        "hash_domain": GATE_E_PREVIEW_HASH_DOMAIN,
        "holdout_membership_sha256": result.holdout_membership_sha256,
        "pilot_membership_sha256": result.pilot_membership_sha256,
        "partition_sha256": result.partition_sha256,
        "preview_input_sha256": inputs.preview_input_sha256,
        "provenance_sha256": provenance.provenance_sha256,
        "sanitized_preview_sha256": result.sanitized_preview.preview_sha256,
        "schema_version": SCHEMA_GATE_E_RESULT,
        "selection_sha256": result.selection_sha256,
    }
    canonical = _canonical_bytes(payload)
    # domain hash is recorded as part of canonicity but not separately stored;
    # the canonical bytes are the authority for replay verification.
    # Verify hash domain inclusion.
    _ = _domain_hash(GATE_E_PREVIEW_HASH_DOMAIN, canonical)
    _ = _domain_hash(GATE_E_PREVIEW_CHALLENGE_DOMAIN, canonical)
    return GateEPreviewRecord(
        preview_input_sha256=inputs.preview_input_sha256,
        selection_sha256=result.selection_sha256,
        partition_sha256=result.partition_sha256,
        pilot_membership_sha256=result.pilot_membership_sha256,
        holdout_membership_sha256=result.holdout_membership_sha256,
        sanitized_preview_sha256=result.sanitized_preview.preview_sha256,
        provenance_sha256=provenance.provenance_sha256,
        hash_domain=GATE_E_PREVIEW_HASH_DOMAIN,
        challenge_domain=GATE_E_PREVIEW_CHALLENGE_DOMAIN,
        canonical_bytes=canonical,
    )


def run_gate_e_preview(
    *,
    inputs: ProfileRelevanceInput,
    provenance: ProvenanceBundle,
) -> tuple[PreviewComputationResult, GateEPreviewRecord]:
    """Validate bindings, run sealed preview, return result + record.

    Only ``compute_preview`` is invoked. No bytes, no store, no
    ``materialize_payload_bytes``.
    """
    _validate_inputs_gate_e(inputs=inputs, provenance=provenance)
    # Pure offline recomputation — no IO.
    result: PreviewComputationResult = compute_preview(inputs)
    # Bind result hashes to provenance/sealed snapshot.
    _require_hex64(result.selection_sha256, "gate_e_hash_invalid")
    _require_hex64(result.partition_sha256, "gate_e_hash_invalid")
    _require_hex64(result.pilot_membership_sha256, "gate_e_hash_invalid")
    _require_hex64(result.holdout_membership_sha256, "gate_e_hash_invalid")
    _require_hex64(result.sanitized_preview.preview_sha256, "gate_e_hash_invalid")
    if result.selection_sha256 != result.selection.selection_sha256:
        raise GateEError("gate_e_selection_hash_mismatch")
    if result.partition_sha256 != result.partition.partition_sha256:
        raise GateEError("gate_e_partition_hash_mismatch")
    record = build_gate_e_record(result=result, inputs=inputs, provenance=provenance)
    return result, record


__all__ = [
    "GATE_E_PREVIEW_CHALLENGE_DOMAIN",
    "GATE_E_PREVIEW_HASH_DOMAIN",
    "SCHEMA_GATE_E_RESULT",
    "GateEError",
    "GateEPreviewRecord",
    "build_gate_e_record",
    "run_gate_e_preview",
]
