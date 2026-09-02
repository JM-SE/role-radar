"""Pure, fail-closed authorization for the R2 Gate E preview.

This module deliberately deals in already verified, immutable artifact objects.  It
does not load artifacts and does not invoke the preview (or any successor gate).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    GateDResult,
    ParentPoolManifest,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import (
    GateDAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    PostCPreregistrationRequest,
    PostCPreregistrationSeal,
    build_seal,
)
from role_radar.evaluation.profile_relevant_acquisition.provenance import ProvenanceBundle

HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
SCHEMA = "f10.1f-gate-e-authorization-v1"


class GateEAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _hash(value: object, code: str) -> None:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        raise GateEAuthorizationError(code)


def _same(left: object, right: object, code: str) -> None:
    if left != right:
        raise GateEAuthorizationError(code)


@dataclass(frozen=True, slots=True)
class GateEAuthorizationRequest:
    """The complete exact chain required before an adapter is reachable."""

    operation_id: str
    lineage_id: str
    gate_d_request: GateDAuthorizationRequest
    gate_d_result: GateDResult
    parent_pool_manifest: ParentPoolManifest
    post_c_request: PostCPreregistrationRequest
    post_c_seal: PostCPreregistrationSeal
    provenance: ProvenanceBundle
    current_commit_sha256: str
    profile_relevance_input: object


@dataclass(frozen=True, slots=True)
class AuthorizedGateE:
    request: GateEAuthorizationRequest


def authorize_gate_e(request: GateEAuthorizationRequest) -> AuthorizedGateE:
    """Reconcile B→C→Post-C→D and the exact sealed parent-pool snapshot."""

    if not isinstance(request, GateEAuthorizationRequest):
        raise GateEAuthorizationError("gate_e_authorization_required")
    if type(request.operation_id) is not str or not request.operation_id.strip():
        raise GateEAuthorizationError("gate_e_operation_invalid")
    if type(request.lineage_id) is not str or not request.lineage_id.strip():
        raise GateEAuthorizationError("gate_e_lineage_invalid")
    _hash(request.current_commit_sha256, "gate_e_commit_invalid")
    post = request.post_c_request
    if not isinstance(post, PostCPreregistrationRequest):
        raise GateEAuthorizationError("gate_e_post_c_required")
    if not isinstance(request.post_c_seal, PostCPreregistrationSeal):
        raise GateEAuthorizationError("gate_e_post_c_seal_invalid")
    try:
        expected_seal = build_seal(post)
    except Exception as exc:
        raise GateEAuthorizationError("gate_e_post_c_invalid") from exc
    if request.post_c_seal != expected_seal:
        raise GateEAuthorizationError("gate_e_post_c_seal_mismatch")
    _same(post.operation_id, request.operation_id, "gate_e_operation_mismatch")
    _same(post.lineage_id, request.lineage_id, "gate_e_lineage_mismatch")
    _same(
        post.provenance.candidate_commit_sha256,
        request.current_commit_sha256,
        "gate_e_commit_mismatch",
    )
    if not isinstance(request.provenance, ProvenanceBundle):
        raise GateEAuthorizationError("gate_e_provenance_invalid")
    _same(request.provenance.namespace, post.provenance.namespace, "gate_e_namespace_mismatch")
    _same(
        request.provenance.query_plan_sha256,
        post.query_plan.plan_sha256,
        "gate_e_query_plan_mismatch",
    )
    _same(request.provenance.root, post.provenance.approved_root, "gate_e_root_mismatch")
    _same(
        request.provenance.corpus_total,
        post.target_corpus_count,
        "gate_e_cardinality_mismatch",
    )
    _same(request.provenance.pilot_count, post.target_pilot_count, "gate_e_cardinality_mismatch")
    _same(
        request.provenance.holdout_count,
        post.target_holdout_count,
        "gate_e_cardinality_mismatch",
    )
    _same(request.gate_d_request.operation_id, request.operation_id, "gate_e_operation_mismatch")
    _same(request.gate_d_request.lineage_id, request.lineage_id, "gate_e_lineage_mismatch")
    _same(request.gate_d_request.post_c_request, post, "gate_e_post_c_substituted")
    _same(request.gate_d_request.post_c_seal, request.post_c_seal, "gate_e_post_c_seal_mismatch")

    result = request.gate_d_result
    manifest = request.parent_pool_manifest
    if not isinstance(result, GateDResult) or not isinstance(manifest, ParentPoolManifest):
        raise GateEAuthorizationError("gate_e_gate_d_required")
    if result.manifest is not manifest:
        raise GateEAuthorizationError("gate_e_manifest_substituted")
    if len({o.external_id for o in result.observations}) != len(result.observations):
        raise GateEAuthorizationError("gate_e_observation_duplicate")
    _same(result.operation_id, request.operation_id, "gate_e_operation_mismatch")
    _same(manifest.operation_id, request.operation_id, "gate_e_operation_mismatch")
    _same(
        manifest.source_plan_sha256,
        post.source_plan.source_plan_sha256,
        "gate_e_source_plan_mismatch",
    )
    _same(
        manifest.preregistration_sha256,
        request.post_c_seal.preregistration_sha256,
        "gate_e_preregistration_mismatch",
    )
    _same(
        manifest.provenance_sha256,
        request.gate_d_request.post_c_request.provenance.gate_b_packet_sha256,
        "gate_e_provenance_mismatch",
    )
    _same(manifest.pool_sha256, result.pool_sha256, "gate_e_pool_mismatch")
    if not isinstance(manifest.canonical_bytes, bytes) or not manifest.canonical_bytes:
        raise GateEAuthorizationError("gate_e_manifest_noncanonical")
    terminal = (manifest.pending_or_indeterminate, manifest.indeterminate, manifest.truncated)
    if any(type(value) is not int or value != 0 for value in terminal):
        raise GateEAuthorizationError("gate_e_reconciliation_nonterminal")
    if manifest.observed != (
        manifest.new_to_pool
        + manifest.duplicate
        + manifest.stale
        + manifest.invalid
        + manifest.conflict
    ):
        raise GateEAuthorizationError("gate_e_reconciliation_mismatch")
    if manifest.observed != len(result.observations):
        raise GateEAuthorizationError("gate_e_observation_count_mismatch")
    if not isinstance(request.gate_d_request.evidence_root, Path) or not (
        request.gate_d_request.evidence_root.is_absolute()
    ):
        raise GateEAuthorizationError("gate_e_root_invalid")
    # Upstream DTOs perform the detailed B/C/Post-C checks; these identity checks
    # ensure the exact objects, rather than hash-shaped substitutes, were supplied.
    if (
        post.gate_c_result.source_plan is not post.source_plan
        or post.gate_c_result.report is not post.gate_c_report
    ):
        raise GateEAuthorizationError("gate_e_upstream_substituted")
    return AuthorizedGateE(request)


__all__ = [
    "SCHEMA",
    "AuthorizedGateE",
    "GateEAuthorizationError",
    "GateEAuthorizationRequest",
    "authorize_gate_e",
]
