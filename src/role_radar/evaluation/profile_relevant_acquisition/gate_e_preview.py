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

from role_radar.evaluation.profile_relevance.contracts import (
    PreviewComputationResult,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevance.hashing import domain_hash_bytes
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_PARTITION_POLICY,
    DOMAIN_POLICY,
    DOMAIN_PREVIEW_COMPUTATION,
    DOMAIN_SAMPLING_POLICY,
    EXECUTION_SCOPE_SYNTHETIC,
    MAX_CANONICAL_BYTES,
    MAX_CORPUS_CARDINALITY,
    MAX_EXCLUSION_DIGESTS,
    MAX_HOLDOUT_CARDINALITY,
    MAX_OBSERVATIONS,
    MAX_PILOT_CARDINALITY,
    MAX_QUOTA_CELLS,
    SCHEMA_INPUT,
)
from role_radar.evaluation.profile_relevance.preview_workflow import compute_preview
from role_radar.evaluation.profile_relevant_acquisition.provenance import (
    ProvenanceBundle,
    ProvenanceError,
    validate_provenance,
)

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
        expected = {
            "challenge_domain": self.challenge_domain,
            "hash_domain": self.hash_domain,
            "holdout_membership_sha256": self.holdout_membership_sha256,
            "pilot_membership_sha256": self.pilot_membership_sha256,
            "partition_sha256": self.partition_sha256,
            "preview_input_sha256": self.preview_input_sha256,
            "provenance_sha256": self.provenance_sha256,
            "sanitized_preview_sha256": self.sanitized_preview_sha256,
            "schema_version": SCHEMA_GATE_E_RESULT,
            "selection_sha256": self.selection_sha256,
        }
        try:
            canonical = _canonical_bytes(expected)
        except GateEError:
            raise
        if canonical != self.canonical_bytes:
            raise GateEError("gate_e_canonical_mismatch")


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
    if not inputs.sealed_snapshot.namespace.strip():
        raise GateEError("gate_e_namespace_invalid")
    if inputs.sealed_snapshot.namespace != provenance.namespace:
        raise GateEError("gate_e_namespace_mismatch")
    # Seeds are explicit F10.1E inputs.  This boundary validates their exact
    # shape and distinctness but never supplies or compares against a module
    # constant; production values can only arrive in an approved artifact.
    for seed, code in (
        (inputs.sampling_policy.selection_seed, "gate_e_selection_seed_invalid"),
        (inputs.partition_policy.partition_seed, "gate_e_partition_seed_invalid"),
    ):
        if (
            not isinstance(seed, str)
            or len(seed) != 64
            or any(char not in "0123456789abcdef" for char in seed)
        ):
            raise GateEError(code)
    if inputs.sampling_policy.selection_seed == inputs.partition_policy.partition_seed:
        raise GateEError("gate_e_seeds_must_differ")
    if inputs.relevance_policy.policy_sha256 != provenance.relevance_policy_sha256:
        raise GateEError("gate_e_policy_mismatch")
    if hashlib.sha256(inputs.sampling_policy.selection_seed.encode("ascii")).hexdigest() != (
        provenance.selection_seed_sha256
    ):
        raise GateEError("gate_e_selection_seed_mismatch")
    if hashlib.sha256(inputs.partition_policy.partition_seed.encode("ascii")).hexdigest() != (
        provenance.partition_seed_sha256
    ):
        raise GateEError("gate_e_partition_seed_mismatch")
    # Binding hashes must be hex.
    _require_hex64(provenance.provenance_sha256, "gate_e_hash_invalid")
    _require_hex64(inputs.preview_input_sha256, "gate_e_hash_invalid")
    _require_hex64(provenance.inventory_sha256, "gate_e_hash_invalid")
    # Historical exclusion digest shape is checked inside compute_preview; we only
    # ensure the preview input binding is present.
    if inputs.input_schema_version != "f10.1e-profile-relevance-input-v1":
        raise GateEError("gate_e_schema_invalid")
    if any(
        policy.execution_scope != EXECUTION_SCOPE_SYNTHETIC
        for policy in (
            inputs.relevance_policy,
            inputs.sampling_policy,
            inputs.partition_policy,
        )
    ):
        raise GateEError("offline_scope_required")
    if inputs.input_schema_version != SCHEMA_INPUT:
        raise GateEError("input_schema_invalid")
    if (
        len(inputs.sealed_snapshot.observations) > MAX_OBSERVATIONS
        or len(inputs.canonical_aggregate_bytes) > MAX_CANONICAL_BYTES
        or len(inputs.historical_exclusion.digests) > MAX_EXCLUSION_DIGESTS
        or len(inputs.sampling_policy.quotas) > MAX_QUOTA_CELLS
        or inputs.sampling_policy.corpus_cardinality > MAX_CORPUS_CARDINALITY
        or inputs.partition_policy.total_count > MAX_HOLDOUT_CARDINALITY + MAX_PILOT_CARDINALITY
        or inputs.partition_policy.pilot_count > MAX_PILOT_CARDINALITY
        or inputs.partition_policy.holdout_count > MAX_HOLDOUT_CARDINALITY
    ):
        raise GateEError("input_limit_exceeded")
    if (
        domain_hash_bytes(DOMAIN_POLICY, inputs.relevance_policy.canonical_bytes)
        != inputs.relevance_policy.policy_sha256
        or domain_hash_bytes(DOMAIN_SAMPLING_POLICY, inputs.sampling_policy.canonical_bytes)
        != inputs.sampling_policy.sampling_policy_sha256
        or domain_hash_bytes(DOMAIN_PARTITION_POLICY, inputs.partition_policy.canonical_bytes)
        != inputs.partition_policy.partition_policy_sha256
    ):
        raise GateEError("gate_e_policy_mismatch")
    if (
        domain_hash_bytes(DOMAIN_PREVIEW_COMPUTATION, inputs.canonical_aggregate_bytes)
        != inputs.preview_input_sha256
    ):
        raise GateEError("gate_e_preview_binding_mismatch")


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
