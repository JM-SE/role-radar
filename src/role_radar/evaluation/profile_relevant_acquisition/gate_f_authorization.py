"""Pure authorization boundary for the offline R2 Gate F operation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from role_radar.evaluation.profile_relevance.contracts import (
    MaterializationContext,
    PreviewComputationResult,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    GateDResult,
    ParentPoolManifest,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import SyntheticTestAdapter
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import FreezeBindings
from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    AuthorizedGateE,
    GateEAuthorizationError,
    GateEAuthorizationRequest,
    authorize_gate_e,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import (
    GateEPreviewRecord,
    build_gate_e_record,
)
from role_radar.evaluation.profile_relevant_acquisition.manifest import build_sealed_pool_manifest
from role_radar.evaluation.profile_relevant_acquisition.provenance import ProvenanceBundle
from role_radar.evaluation.profile_relevant_acquisition.source_plan import SourcePlan

HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class GateFAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _hash(value: object, code: str) -> None:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise GateFAuthorizationError(code)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _verify_d_graph(request: GateFAuthorizationRequest) -> None:
    """Re-bind the complete D snapshot; identity checks alone are insufficient."""
    result, manifest, snapshot = (
        request.gate_d_result,
        request.parent_pool_manifest,
        request.profile_relevance_input.sealed_snapshot,
    )
    if not isinstance(result, GateDResult) or not isinstance(manifest, ParentPoolManifest):
        raise GateFAuthorizationError("gate_f_d_snapshot_invalid")
    if manifest is not result.manifest or manifest.pool_sha256 != result.pool_sha256:
        raise GateFAuthorizationError("gate_f_manifest_substituted")
    plan = request.gate_e_request.post_c_request.source_plan
    if not isinstance(plan, SourcePlan):
        raise GateFAuthorizationError("gate_f_source_plan_invalid")
    if hashlib.sha256(plan.canonical_bytes).hexdigest() != plan.source_plan_sha256:
        raise GateFAuthorizationError("gate_f_source_plan_hash_mismatch")
    if plan.canonical_bytes != _canonical(plan._payload()):
        raise GateFAuthorizationError("gate_f_source_plan_noncanonical")
    if manifest.source_plan_sha256 != plan.source_plan_sha256:
        raise GateFAuthorizationError("gate_f_source_plan_mismatch")
    manifest_payload = {
        name: getattr(manifest, name)
        for name in (
            "operation_id",
            "source_plan_sha256",
            "preregistration_sha256",
            "provenance_sha256",
            "observed",
            "new_to_pool",
            "duplicate",
            "stale",
            "invalid",
            "conflict",
            "truncated",
            "indeterminate",
            "durable_intents",
            "known_terminal_outcomes",
            "pending_or_indeterminate",
            "delegate_entries",
            "budget_debits",
            "collector_wire_attempts",
            "budget_consumed",
            "checkpoint_wire_attempts",
            "pool_sha256",
        )
    }
    if manifest.canonical_bytes != _canonical(manifest_payload):
        raise GateFAuthorizationError("gate_f_manifest_noncanonical")
    if any(
        getattr(manifest, name) != 0
        for name in (
            "truncated",
            "indeterminate",
            "pending_or_indeterminate",
            "duplicate",
            "stale",
            "invalid",
            "conflict",
        )
    ):
        raise GateFAuthorizationError("gate_f_d_reconciliation_invalid")
    if manifest.observed != manifest.new_to_pool or manifest.observed != len(result.observations):
        raise GateFAuthorizationError("gate_f_d_reconciliation_invalid")
    if len({o.external_id for o in result.observations}) != len(result.observations):
        raise GateFAuthorizationError("gate_f_observation_duplicate")
    pool_bytes = _canonical(sorted(o.canonical_sha256 for o in result.observations))
    if hashlib.sha256(pool_bytes).hexdigest() != manifest.pool_sha256:
        raise GateFAuthorizationError("gate_f_pool_binding_mismatch")
    if snapshot.state != "sealed" or len(snapshot.observations) != len(result.observations):
        raise GateFAuthorizationError("gate_f_snapshot_invalid")
    for observed, sealed in zip(result.observations, snapshot.observations, strict=True):
        if not isinstance(observed.canonical_bytes, bytes):
            raise GateFAuthorizationError("gate_f_observation_unsealed")
        try:
            observed_object = json.loads(observed.canonical_bytes.decode())
            if not isinstance(observed_object, dict) or observed.canonical_bytes != _canonical(
                observed_object
            ):
                raise ValueError
        except (UnicodeError, ValueError, TypeError):
            raise GateFAuthorizationError("gate_f_observation_noncanonical") from None
        if hashlib.sha256(observed.canonical_bytes).hexdigest() != observed.canonical_sha256:
            raise GateFAuthorizationError("gate_f_observation_hash_mismatch")
        if (
            sealed.observation_id,
            sealed.source.source_id,
            sealed.source.board_key,
            sealed.title,
            sealed.location,
            sealed.description,
        ) != (
            observed.external_id,
            observed.source_id,
            observed.source_key,
            observed.title,
            observed.location or "",
            observed.description or "",
        ):
            raise GateFAuthorizationError("gate_f_observation_substituted")
        if (
            not isinstance(sealed.canonical_observation_bytes, bytes)
            or not sealed.canonical_observation_bytes
        ):
            raise GateFAuthorizationError("gate_f_observation_unsealed")
        try:
            sealed_object = json.loads(sealed.canonical_observation_bytes.decode())
            if not isinstance(
                sealed_object, dict
            ) or sealed.canonical_observation_bytes != _canonical(sealed_object):
                raise ValueError
        except (UnicodeError, ValueError, TypeError):
            raise GateFAuthorizationError("gate_f_observation_noncanonical") from None
        if any(
            observed_object.get(key) != sealed_object.get(key)
            for key in (
                "source_id",
                "source_key",
                "external_id",
                "title",
                "location",
                "description",
            )
        ):
            raise GateFAuthorizationError("gate_f_observation_substituted")
    try:
        expected = build_sealed_pool_manifest(
            dataset_id=request.dataset_id,
            pool_sha256=manifest.pool_sha256,
            provenance_sha256=manifest.provenance_sha256,
            source_plan_sha256=manifest.source_plan_sha256,
            inventory_sha256=request.provenance.inventory_sha256,
            preview_input_sha256=request.gate_e_record.preview_input_sha256,
            selection_sha256=request.gate_e_result.selection_sha256,
            partition_sha256=request.gate_e_result.partition_sha256,
            pilot_membership_sha256=request.gate_e_result.pilot_membership_sha256,
            holdout_membership_sha256=request.gate_e_result.holdout_membership_sha256,
            observation_count=len(snapshot.observations),
            corpus_count=request.profile_relevance_input.partition_policy.total_count,
            pilot_count=request.profile_relevance_input.partition_policy.pilot_count,
            holdout_count=request.profile_relevance_input.partition_policy.holdout_count,
        )
    except Exception as exc:
        raise GateFAuthorizationError("gate_f_sealed_pool_invalid") from exc
    # This proves all semantic fields and the canonical D pool binding are the same source.
    if expected.pool_sha256 != manifest.pool_sha256:
        raise GateFAuthorizationError("gate_f_pool_binding_mismatch")


@dataclass(frozen=True, slots=True)
class GateFAuthorization:
    operation_id: str
    lineage_id: str
    challenge_sha256: str
    expires_at_utc: str
    artifact_class: str
    test_only_adapter: SyntheticTestAdapter


@dataclass(frozen=True, slots=True)
class GateFAuthorizationRequest:
    """Complete, explicit B→E graph.  No field is optional by design."""

    authorization: GateFAuthorization
    gate_e_request: GateEAuthorizationRequest
    gate_d_result: GateDResult
    parent_pool_manifest: ParentPoolManifest
    provenance: ProvenanceBundle
    profile_relevance_input: ProfileRelevanceInput
    gate_e_record: GateEPreviewRecord
    gate_e_result: PreviewComputationResult
    materialization_context: MaterializationContext
    dataset_id: str
    destination_root: Path


@dataclass(frozen=True, slots=True)
class AuthorizedGateF:
    request: GateFAuthorizationRequest
    gate_e: AuthorizedGateE


def freeze_bindings_for_request(request: GateFAuthorizationRequest) -> FreezeBindings:
    """Derive the only freeze binding set accepted by Gate F."""
    result = request.gate_e_result
    manifest = request.parent_pool_manifest
    inputs = request.profile_relevance_input
    auth = request.authorization
    return FreezeBindings(
        dataset_id=request.dataset_id,
        pool_sha256=manifest.pool_sha256,
        provenance_sha256=request.provenance.provenance_sha256,
        f_challenge_sha256=auth.challenge_sha256,
        inventory_sha256=request.provenance.inventory_sha256,
        source_plan_sha256=inputs.sealed_snapshot.source_plan_sha256,
        preview_input_sha256=request.gate_e_record.preview_input_sha256,
        selection_sha256=result.selection_sha256,
        partition_sha256=result.partition_sha256,
        pilot_membership_sha256=result.pilot_membership_sha256,
        holdout_membership_sha256=result.holdout_membership_sha256,
        observation_count=len(inputs.sealed_snapshot.observations),
        corpus_count=inputs.partition_policy.total_count,
        pilot_count=inputs.partition_policy.pilot_count,
        holdout_count=inputs.partition_policy.holdout_count,
        per_board_cap=inputs.sampling_policy.per_board_cap,
        per_company_cap=inputs.sampling_policy.global_per_company_cap,
        namespace=request.provenance.namespace,
        root=request.provenance.root,
    )


def authorize_gate_f(
    request: GateFAuthorizationRequest, *, now: datetime | None = None
) -> AuthorizedGateF:
    if not isinstance(request, GateFAuthorizationRequest):
        raise GateFAuthorizationError("gate_f_authorization_required")
    auth = request.authorization
    if not isinstance(auth, GateFAuthorization) or not isinstance(
        auth.test_only_adapter, SyntheticTestAdapter
    ):
        raise GateFAuthorizationError("gate_f_synthetic_adapter_required")
    if (
        type(auth.artifact_class) is not str
        or type(auth.operation_id) is not str
        or type(auth.lineage_id) is not str
        or auth.artifact_class != "synthetic"
        or not auth.operation_id.strip()
        or not auth.lineage_id.strip()
    ):
        raise GateFAuthorizationError("gate_f_authorization_invalid")
    _hash(auth.challenge_sha256, "gate_f_challenge_invalid")
    if type(auth.expires_at_utc) is not str or not auth.expires_at_utc.endswith("Z"):
        raise GateFAuthorizationError("gate_f_expiry_invalid")
    try:
        expiry = datetime.fromisoformat(auth.expires_at_utc[:-1] + "+00:00")
        clock = datetime.now(UTC) if now is None else now.astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise GateFAuthorizationError("gate_f_expiry_invalid") from exc
    if expiry.tzinfo is not UTC or clock >= expiry:
        raise GateFAuthorizationError("authorization_expired")
    if (
        type(request.dataset_id) is not str
        or not HEX64.fullmatch(request.dataset_id)
        or not isinstance(request.destination_root, Path)
        or not request.destination_root.is_absolute()
    ):
        raise GateFAuthorizationError("gate_f_destination_invalid")
    try:
        gate_e = authorize_gate_e(request.gate_e_request, now=clock)
    except GateEAuthorizationError as exc:
        raise GateFAuthorizationError(exc.code) from exc
    if gate_e.request.operation_id != auth.operation_id or gate_e.request.lineage_id != (
        auth.lineage_id
    ):
        raise GateFAuthorizationError("gate_f_operation_lineage_mismatch")
    if str(request.destination_root) != request.provenance.root:
        raise GateFAuthorizationError("gate_f_root_mismatch")
    if gate_e.request.gate_d_result is not request.gate_d_result or (
        gate_e.request.parent_pool_manifest is not request.parent_pool_manifest
    ):
        raise GateFAuthorizationError("gate_f_d_snapshot_substituted")
    if gate_e.request.provenance is not request.provenance or (
        gate_e.request.profile_relevance_input is not request.profile_relevance_input
    ):
        raise GateFAuthorizationError("gate_f_input_substituted")
    _verify_d_graph(request)
    if not isinstance(request.gate_e_record, GateEPreviewRecord) or not isinstance(
        request.gate_e_result, PreviewComputationResult
    ):
        raise GateFAuthorizationError("gate_f_e_result_required")
    record = request.gate_e_record
    result = request.gate_e_result
    inputs = request.profile_relevance_input
    if request.provenance.provenance_sha256 != record.provenance_sha256:
        raise GateFAuthorizationError("gate_f_provenance_mismatch")
    result_hashes = (
        result.selection_sha256,
        result.partition_sha256,
        result.pilot_membership_sha256,
        result.holdout_membership_sha256,
    )
    record_hashes = (
        record.selection_sha256,
        record.partition_sha256,
        record.pilot_membership_sha256,
        record.holdout_membership_sha256,
    )
    if result_hashes != record_hashes:
        raise GateFAuthorizationError("gate_f_e_hash_mismatch")
    try:
        if (
            build_gate_e_record(
                result=result,
                inputs=request.profile_relevance_input,
                provenance=request.provenance,
            )
            != record
        ):
            raise GateFAuthorizationError("gate_f_e_record_noncanonical")
        manifest_object = json.loads(request.parent_pool_manifest.canonical_bytes.decode("utf-8"))
        if not isinstance(manifest_object, dict):
            raise ValueError
        canonical_manifest = json.dumps(
            manifest_object, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except GateFAuthorizationError:
        raise
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise GateFAuthorizationError("gate_f_manifest_noncanonical") from exc
    if canonical_manifest != request.parent_pool_manifest.canonical_bytes:
        raise GateFAuthorizationError("gate_f_manifest_noncanonical")
    if not isinstance(request.materialization_context, MaterializationContext) or (
        request.materialization_context.inputs is not request.profile_relevance_input
    ):
        raise GateFAuthorizationError("gate_f_materialization_context_invalid")
    if result.sanitized_preview.preview_sha256 != record.sanitized_preview_sha256:
        raise GateFAuthorizationError("gate_f_e_hash_mismatch")
    if result.selection.selected_count != result.selection.corpus_count:
        raise GateFAuthorizationError("gate_f_e_cardinality_mismatch")
    if len(result.partition.pilot_item_hashes) != inputs.partition_policy.pilot_count or (
        len(result.partition.holdout_item_hashes) != inputs.partition_policy.holdout_count
    ):
        raise GateFAuthorizationError("gate_f_e_cardinality_mismatch")
    try:
        derived = freeze_bindings_for_request(request)
    except (TypeError, ValueError) as exc:
        raise GateFAuthorizationError("gate_f_binding_invalid") from exc
    if not isinstance(derived, FreezeBindings):
        raise GateFAuthorizationError("gate_f_binding_invalid")
    return AuthorizedGateF(request, gate_e)


__all__ = [
    "AuthorizedGateF",
    "GateFAuthorization",
    "GateFAuthorizationError",
    "GateFAuthorizationRequest",
    "authorize_gate_f",
    "freeze_bindings_for_request",
]
