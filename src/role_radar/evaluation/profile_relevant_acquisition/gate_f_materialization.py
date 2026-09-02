"""Gate F — materialization only.

Validates ``ApprovedPreview`` + ``MaterializationContext`` over the
sealed parent pool, recomputes ``compute_preview`` requiring exact equality
to the approved bindings (per F10.1E), then constructs ``MaterializedPayloads``
bytes via ``materialize_payload_bytes``. No live synthesis, no network,
no collection, no store. Bytes are returned to the caller for the single
freeze transaction — Gate F is the sole materializer.
"""

from __future__ import annotations

import hashlib
import json
from typing import Final

from role_radar.evaluation.profile_relevance.contracts import (
    ApprovedPreview,
    MaterializationContext,
    MaterializedPayloads,
    PreviewComputationResult,
)
from role_radar.evaluation.profile_relevance.materialization import materialize_payload_bytes
from role_radar.evaluation.profile_relevance.preview_workflow import compute_preview
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    AuthorizationError,
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
    SyntheticTestAdapter,
    require_execution_boundary,
)

GATE_F_MATERIALIZATION_HASH_DOMAIN: Final[str] = "role-radar:f10.1f:gate-f:materialization-hash:v1"
GATE_F_MATERIALIZATION_CHALLENGE_DOMAIN: Final[str] = "role-radar:f10.1f:gate-f:challenge:v1"


class GateFError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise GateFError(code)
    if any(c not in "0123456789abcdef" for c in value):
        raise GateFError(code)


def _validate_approved_preview(value: object) -> ApprovedPreview:
    if not isinstance(value, ApprovedPreview):
        raise GateFError("gate_f_approved_preview_invalid")
    for name in (
        "preview_input_sha256",
        "selection_sha256",
        "partition_sha256",
        "pilot_membership_sha256",
        "holdout_membership_sha256",
        "approval_binding_sha256",
        "operation_binding_sha256",
        "lineage_binding_sha256",
    ):
        _require_hex64(getattr(value, name), "gate_f_hash_invalid")
    if value.schema_version != "f10.1e-profile-relevance-approved-preview-v1":
        raise GateFError("gate_f_schema_invalid")
    return value


def _validate_materialization_context(value: object) -> MaterializationContext:
    if not isinstance(value, MaterializationContext):
        raise GateFError("gate_f_materialization_context_invalid")
    _require_hex64(value.materialization_context_sha256, "gate_f_hash_invalid")
    _require_hex64(value.operation_binding_sha256, "gate_f_hash_invalid")
    _require_hex64(value.lineage_binding_sha256, "gate_f_hash_invalid")
    if value.schema_version != "f10.1e-profile-relevance-materialization-context-v1":
        raise GateFError("gate_f_schema_invalid")
    if value.materialization_domain != "role-radar:f10.1e-profile-relevance:materialization:v1":
        raise GateFError("gate_f_domain_invalid")
    # Expected preview must be the same object identity as approved preview binding.
    if not isinstance(value.expected_approved_preview, ApprovedPreview):
        raise GateFError("gate_f_materialization_context_invalid")
    return value


def _recompute_and_require_exact_equality(
    *,
    approved_preview: ApprovedPreview,
    materialization_context: MaterializationContext,
    approved_result: PreviewComputationResult | None = None,
) -> None:
    # Cross-gate substitution guards before recompute.
    if materialization_context.expected_approved_preview != approved_preview:
        raise GateFError("gate_f_cross_gate_substitution")
    if (
        materialization_context.operation_binding_sha256
        != approved_preview.operation_binding_sha256
    ):
        raise GateFError("gate_f_cross_gate_substitution")
    if materialization_context.lineage_binding_sha256 != approved_preview.lineage_binding_sha256:
        raise GateFError("gate_f_cross_gate_substitution")

    recomputed = approved_result or compute_preview(materialization_context.inputs)

    inputs = materialization_context.inputs
    if inputs.preview_input_sha256 != approved_preview.preview_input_sha256:
        raise GateFError("gate_f_preview_binding_mismatch")
    if recomputed.selection_sha256 != approved_preview.selection_sha256:
        raise GateFError("gate_f_selection_hash_mismatch")
    if recomputed.partition_sha256 != approved_preview.partition_sha256:
        raise GateFError("gate_f_partition_hash_mismatch")
    if recomputed.pilot_membership_sha256 != approved_preview.pilot_membership_sha256:
        raise GateFError("gate_f_pilot_membership_mismatch")
    if recomputed.holdout_membership_sha256 != approved_preview.holdout_membership_sha256:
        raise GateFError("gate_f_holdout_membership_mismatch")

    # Legacy callers retain deterministic recomputation; Gate F consumes the
    # exact E result and deliberately does not rerun selection/partition.
    if approved_result is None:
        recomputed2 = compute_preview(materialization_context.inputs)
        if recomputed2.selection_sha256 != recomputed.selection_sha256:
            raise GateFError("gate_f_recompute_mismatch")
        if recomputed2.partition_sha256 != recomputed.partition_sha256:
            raise GateFError("gate_f_recompute_mismatch")


def run_gate_f_materialization(
    *,
    approved_preview: ApprovedPreview,
    materialization_context: MaterializationContext,
    test_only_adapter: SyntheticTestAdapter | None = None,
    approved_result: PreviewComputationResult | None = None,
    approval: ExternalApprovalBinding | None = None,
    approval_verifier: ExternalApprovalVerifier | None = None,
) -> MaterializedPayloads:
    """Validate, recompute with exact equality, then materialize payload bytes.

    This is the sole live gate permitted to call ``materialize_payload_bytes``.
    """
    ap = _validate_approved_preview(approved_preview)
    try:
        require_execution_boundary(
            artifact_sha256=ap.preview_input_sha256,
            test_only_adapter=test_only_adapter,
            approval=approval,
            approval_verifier=approval_verifier,
            code="gate_f_execution_authorization_required",
        )
    except AuthorizationError as exc:
        raise GateFError(exc.code) from exc
    if approval is not None and approval.approval_binding_sha256 != ap.approval_binding_sha256:
        raise GateFError("gate_f_approval_binding_mismatch")
    ctx = _validate_materialization_context(materialization_context)
    _recompute_and_require_exact_equality(
        approved_preview=ap,
        materialization_context=ctx,
        approved_result=approved_result,
    )
    # Materialization recomputes/verifies bindings again before byte construction.
    payloads: MaterializedPayloads = materialize_payload_bytes(
        ap, ctx, approved_result=approved_result
    )
    # Payload contracts: six private, one operator, two pilot, two holdout.
    if len(payloads.private_payloads) != 6:
        raise GateFError("gate_f_private_payload_count_invalid")
    if len(payloads.operator_payloads) != 1:
        raise GateFError("gate_f_operator_payload_count_invalid")
    if len(payloads.pilot_payloads) != 2:
        raise GateFError("gate_f_pilot_payload_count_invalid")
    if len(payloads.holdout_payloads) != 2:
        raise GateFError("gate_f_holdout_payload_count_invalid")
    # Ensure holdout bytes exist only here — verify holdout view is non-empty.
    holdout_names = {p.logical_name for p in payloads.holdout_payloads}
    if holdout_names != {"holdout_binding", "holdout_sealed_view"}:
        raise GateFError("gate_f_holdout_payload_invalid")
    # No live synthesis or display formatting beyond what materialize does
    # (F10.2A derived values are already in MaterializationContext).
    return payloads


def verify_gate_f_hash_domains() -> None:
    """Fail if domains collide with Gate E or each other."""
    from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import (
        GATE_E_PREVIEW_CHALLENGE_DOMAIN,
        GATE_E_PREVIEW_HASH_DOMAIN,
    )

    domains = {
        GATE_E_PREVIEW_HASH_DOMAIN,
        GATE_E_PREVIEW_CHALLENGE_DOMAIN,
        GATE_F_MATERIALIZATION_HASH_DOMAIN,
        GATE_F_MATERIALIZATION_CHALLENGE_DOMAIN,
    }
    if len(domains) != 4:
        raise GateFError("gate_f_domain_collision")


# -- canonical helpers for Gate F challenge binding (no IO) --


def gate_f_challenge_canonical(
    *,
    preview_input_sha256: str,
    selection_sha256: str,
    partition_sha256: str,
    pilot_membership_sha256: str,
    holdout_membership_sha256: str,
    approval_binding_sha256: str,
    operation_binding_sha256: str,
    lineage_binding_sha256: str,
    materialization_context_sha256: str,
) -> bytes:
    payload: dict[str, object] = {
        "approval_binding_sha256": approval_binding_sha256,
        "challenge_domain": GATE_F_MATERIALIZATION_CHALLENGE_DOMAIN,
        "hash_domain": GATE_F_MATERIALIZATION_HASH_DOMAIN,
        "holdout_membership_sha256": holdout_membership_sha256,
        "lineage_binding_sha256": lineage_binding_sha256,
        "materialization_context_sha256": materialization_context_sha256,
        "operation_binding_sha256": operation_binding_sha256,
        "partition_sha256": partition_sha256,
        "pilot_membership_sha256": pilot_membership_sha256,
        "preview_input_sha256": preview_input_sha256,
        "selection_sha256": selection_sha256,
    }
    for key in (
        "preview_input_sha256",
        "selection_sha256",
        "partition_sha256",
        "pilot_membership_sha256",
        "holdout_membership_sha256",
        "approval_binding_sha256",
        "operation_binding_sha256",
        "lineage_binding_sha256",
        "materialization_context_sha256",
    ):
        _require_hex64(str(payload[key]), "gate_f_hash_invalid")
    try:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise GateFError("gate_f_canonical_invalid") from exc
    raw = text.encode("utf-8")
    # Prove domain inclusion
    for domain in (
        GATE_F_MATERIALIZATION_HASH_DOMAIN,
        GATE_F_MATERIALIZATION_CHALLENGE_DOMAIN,
    ):
        h = hashlib.sha256()
        h.update(domain.encode("ascii"))
        h.update(b"\x00")
        h.update(raw)
        _ = h.hexdigest()
    return raw


__all__ = [
    "GATE_F_MATERIALIZATION_CHALLENGE_DOMAIN",
    "GATE_F_MATERIALIZATION_HASH_DOMAIN",
    "GateFError",
    "gate_f_challenge_canonical",
    "run_gate_f_materialization",
    "verify_gate_f_hash_domains",
]
