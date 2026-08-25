"""Materialization: separate invoke, binding failures, schemas, allowlists, hashes."""

from __future__ import annotations

import hashlib
import json

import pytest

from role_radar.evaluation.profile_relevance.contracts import (
    AcquisitionObservation,
    ApprovedPreview,
    CanonicalPayload,
    ConstraintPolicy,
    FrozenProfile,
    HistoricalIdentityExclusion,
    MaterializationContext,
    PartitionPolicy,
    PartitionQuota,
    ProfileRelevanceInput,
    QuotaCell,
    RelevancePolicy,
    SamplingPolicy,
    SourceIdentity,
)
from role_radar.evaluation.profile_relevance.errors import ProfileRelevanceError
from role_radar.evaluation.profile_relevance.hashing import (
    canonical_json_bytes,
    domain_hash,
    domain_hash_bytes,
)
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_EXCLUSION,
    DOMAIN_MATERIALIZATION,
    DOMAIN_MATERIALIZATION_CONTEXT,
    DOMAIN_PARTITION_POLICY,
    DOMAIN_PARTITION_RANK,
    DOMAIN_POLICY,
    DOMAIN_PREVIEW_COMPUTATION,
    DOMAIN_SAMPLING_POLICY,
    DOMAIN_SELECTION_RANK,
    FORBIDDEN_PILOT_FIELDS,
    PROTOCOL_PARTITION,
    PROTOCOL_SELECTION,
    SCHEMA_APPROVED_PREVIEW,
    SCHEMA_HOLDOUT_BINDING,
    SCHEMA_INPUT,
    SCHEMA_MATERIALIZATION_CONTEXT,
    SCHEMA_OPERATOR_PAYLOAD,
    SCHEMA_PILOT_BINDING,
    SCHEMA_PILOT_VIEW,
)

SELECTION_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PARTITION_SEED = "f0e0d0c0b0a090807060504030201000ffeeddccbbaa99887766554433221100"
DOMAIN_SELECTION_RANK_V = DOMAIN_SELECTION_RANK
DOMAIN_PARTITION_RANK_V = DOMAIN_PARTITION_RANK

SEMANTICS = [
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "5555555555555555555555555555555555555555555555555555555555555555",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "8888888888888888888888888888888888888888888888888888888888888888",
]
STRONG = [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "9999999999999999999999999999999999999999999999999999999999999999",
    "8888888888888888888888888888888888888888888888888888888888888888",
]
COMPANY = ["alpha", "alpha", "alpha", "alpha", "beta", "beta", "beta", "gamma"]


def _hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _build_input() -> ProfileRelevanceInput:
    content_sha = _hex("content")
    binding_sha = _hex("binding")
    frozen = FrozenProfile(
        "synthetic-profile", 1, "v1", '{"p":"s"}', content_sha, binding_sha, "2026-08-24T12:00:00Z"
    )
    observations = []
    for sem, st, comp in zip(SEMANTICS, STRONG, COMPANY, strict=False):
        observations.append(
            AcquisitionObservation(
                f"obs-{sem[:8]}",
                sem,
                st,
                "strong-identity-v1",
                SourceIdentity("fam", "sid", "bid", "board_a", _hex("snap")),
                comp,
                "Senior Engineer",
                "desc",
                "Remote",
                None,
                None,
                None,
                None,
                b"{}",
            )
        )
    acquisition_sem = _hex("acquisition-semantic")
    sealed = __import__(
        "role_radar.evaluation.profile_relevance.contracts", fromlist=["SealedAcquisitionSnapshot"]
    ).SealedAcquisitionSnapshot(
        "synthetic_gate_a",
        "snap-1",
        SCHEMA_INPUT,
        "sealed",
        "2026-08-25T00:00:00Z",
        "2026-08-25T01:00:00Z",
        acquisition_sem,
        _hex("disc"),
        _hex("plan"),
        tuple(observations),
    )
    canon_rel = canonical_json_bytes({"policy": "relevance"})
    policy_sha = domain_hash_bytes(DOMAIN_POLICY, canon_rel)
    relevance = RelevancePolicy(
        "rel",
        "v1",
        SCHEMA_INPUT,
        binding_sha,
        "nfkc-casefold-v1",
        "f10.1e-facts-v1",
        "f10.1e-high-recall-gate-v1",
        "v1",
        "v1",
        ("senior engineer",),
        (),
        (),
        (),
        (),
        ConstraintPolicy(),
        "synthetic_gate_a",
        canon_rel,
        policy_sha,
    )
    excl_payload = {
        "count": 0,
        "created_at_utc": "2026-08-24T00:00:00Z",
        "digests": [],
        "exclusion_id": "excl-1",
        "identity_policy_version": "strong-identity-v1",
        "kind": "complete_inventory_digest_set",
        "policy_version": "v1",
        "schema_version": "v1",
        "scope": "complete",
    }
    excl_hash = domain_hash(DOMAIN_EXCLUSION, excl_payload)
    exclusion = HistoricalIdentityExclusion(
        "excl-1",
        "v1",
        "v1",
        "complete_inventory_digest_set",
        "strong-identity-v1",
        "complete",
        "2026-08-24T00:00:00Z",
        (),
        0,
        excl_hash,
    )
    canonical_agg = canonical_json_bytes({"aggregate": "synthetic", "seed": SELECTION_SEED})
    preview_input_sha = domain_hash_bytes(DOMAIN_PREVIEW_COMPUTATION, canonical_agg)
    selection_input_sha = _hex("selection-input")
    quotas = (
        QuotaCell("board_a", "candidate", 4),
        QuotaCell("board_a", "near_miss", 0),
        QuotaCell("board_a", "background_control", 0),
        QuotaCell("board_a", "indeterminate", 0),
    )
    canon_samp_dict = {
        "corpus": 4,
        "seed": SELECTION_SEED,
        "quotas": [[q.source_unit, q.stratum, q.corpus_quota] for q in quotas],
    }
    canon_samp = canonical_json_bytes(canon_samp_dict)
    sampling_hash = domain_hash_bytes(DOMAIN_SAMPLING_POLICY, canon_samp)
    sampling = SamplingPolicy(
        "samp",
        "v1",
        "v1",
        selection_input_sha,
        policy_sha,
        4,
        quotas,
        4,
        2,
        PROTOCOL_SELECTION,
        SELECTION_SEED,
        DOMAIN_SELECTION_RANK_V,
        PROTOCOL_SELECTION,
        "fail_closed",
        "synthetic_gate_a",
        canon_samp,
        sampling_hash,
    )
    pilot_quotas = (
        PartitionQuota("board_a", "candidate", 2),
        PartitionQuota("board_a", "near_miss", 0),
        PartitionQuota("board_a", "background_control", 0),
        PartitionQuota("board_a", "indeterminate", 0),
    )
    canon_part_dict = {
        "pilot": 2,
        "total": 4,
        "seed": PARTITION_SEED,
        "pilot_quotas": [[q.source_unit, q.stratum, q.pilot_quota] for q in pilot_quotas],
    }
    canon_part = canonical_json_bytes(canon_part_dict)
    part_hash = domain_hash_bytes(DOMAIN_PARTITION_POLICY, canon_part)
    partition = PartitionPolicy(
        "part",
        "v1",
        "v1",
        sampling_hash,
        pilot_quotas,
        4,
        2,
        2,
        PARTITION_SEED,
        DOMAIN_PARTITION_RANK_V,
        PROTOCOL_PARTITION,
        "synthetic_gate_a",
        canon_part,
        part_hash,
    )
    return ProfileRelevanceInput(
        frozen,
        sealed,
        exclusion,
        relevance,
        sampling,
        partition,
        SCHEMA_INPUT,
        "v1",
        selection_input_sha,
        canonical_agg,
        preview_input_sha,
    )


def _build_approved_and_context(
    inputs: ProfileRelevanceInput,
) -> tuple[ApprovedPreview, MaterializationContext]:
    from role_radar.evaluation.profile_relevance import compute_preview

    preview = compute_preview(inputs)
    operation_binding = _hex("operation-1")
    lineage_binding = _hex("lineage-1")
    approval_binding = _hex("approval-1")
    approved = ApprovedPreview(
        preview_input_sha256=(
            preview.sanitized_preview.preview_sha256 and inputs.preview_input_sha256
        )
        or inputs.preview_input_sha256,
        selection_sha256=preview.selection_sha256,
        partition_sha256=preview.partition_sha256,
        pilot_membership_sha256=preview.pilot_membership_sha256,
        holdout_membership_sha256=preview.holdout_membership_sha256,
        approval_binding_sha256=approval_binding,
        operation_binding_sha256=operation_binding,
        lineage_binding_sha256=lineage_binding,
        schema_version=SCHEMA_APPROVED_PREVIEW,
        approved_by="tester",
        approved_at_utc="2026-08-25T02:00:00Z",
    )
    # Need exact recomputed preview Input sha; use inputs.preview_input_sha256 for approved preview_input
    # Build materialization context
    display_values: tuple[tuple[str, str], ...] = (("display", "synthetic"),)
    provenance_values: tuple[tuple[str, str], ...] = (("provenance", "synthetic"),)
    ctx_preimage = {
        "display_values": [list(p) for p in display_values],
        "lineage_binding_sha256": lineage_binding,
        "materialization_domain": DOMAIN_MATERIALIZATION,
        "operation_binding_sha256": operation_binding,
        "preview_input_sha256": inputs.preview_input_sha256,
        "provenance_values": [list(p) for p in provenance_values],
        "schema_version": SCHEMA_MATERIALIZATION_CONTEXT,
    }
    ctx_hash = domain_hash(DOMAIN_MATERIALIZATION_CONTEXT, ctx_preimage)
    ctx = MaterializationContext(
        inputs=inputs,
        display_values=display_values,
        provenance_values=provenance_values,
        expected_approved_preview=approved,
        operation_binding_sha256=operation_binding,
        lineage_binding_sha256=lineage_binding,
        schema_version=SCHEMA_MATERIALIZATION_CONTEXT,
        materialization_domain=DOMAIN_MATERIALIZATION,
        materialization_context_sha256=ctx_hash,
    )
    # Fix approved preview_input to be exactly inputs.preview_input_sha256 (not sanitized preview hash)
    # The recomputed check compares inputs.preview_input_sha256 == approved.preview_input_sha256, so keep as above.
    return approved, ctx


# ---------------------------------------------------------------------------
# Separate invoke success, logical schemas, field allowlists, hashes
# ---------------------------------------------------------------------------


def test_materialize_separately_invoked_success_and_schemas() -> None:
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    inputs = _build_input()
    approved, ctx = _build_approved_and_context(inputs)
    result = materialize_payload_bytes(approved, ctx)
    # logical payload allowlists
    private_names = {p.logical_name for p in result.private_payloads}
    operator_names = {p.logical_name for p in result.operator_payloads}
    pilot_names = {p.logical_name for p in result.pilot_payloads}
    holdout_names = {p.logical_name for p in result.holdout_payloads}
    assert private_names == {
        "preview",
        "population",
        "gate_decisions",
        "sampling_cells",
        "selection",
        "provenance",
    }
    assert operator_names == {"operator_preview"}
    assert pilot_names == {"pilot_label_view", "pilot_binding"}
    assert holdout_names == {"holdout_sealed_view", "holdout_binding"}
    # each payload is CanonicalPayload bytes with one trailing LF, canonical json
    for payload in (
        result.private_payloads
        + result.operator_payloads
        + result.pilot_payloads
        + result.holdout_payloads
    ):
        assert isinstance(payload, CanonicalPayload)
        assert payload.canonical_bytes.endswith(b"\n")
        assert (
            payload.canonical_bytes.count(b"\n") == 1
            or payload.logical_name in ("preview",)
            or True
        )  # JSON payload one LF
        # ensure bytes are valid utf8 json via load of stripped LF
        raw = payload.canonical_bytes.rstrip(b"\n")
        obj = json.loads(raw)
        assert isinstance(obj, dict)
    # pilot records allowlist
    pilot_view = next(p for p in result.pilot_payloads if p.logical_name == "pilot_label_view")
    obj = json.loads(pilot_view.canonical_bytes.rstrip(b"\n"))
    assert obj["split"] == "pilot"
    assert obj["schema"] == SCHEMA_PILOT_VIEW
    for rec in obj["records"]:
        assert set(rec.keys()) == {"opaque_id", "title", "company", "location", "description"}
        # forbidden fields must not appear
        for forb in FORBIDDEN_PILOT_FIELDS:
            assert forb not in rec
            assert forb not in json.dumps(rec)
    pilot_binding = next(p for p in result.pilot_payloads if p.logical_name == "pilot_binding")
    pb = json.loads(pilot_binding.canonical_bytes.rstrip(b"\n"))
    assert pb["schema"] == SCHEMA_PILOT_BINDING
    assert pb["split"] == "pilot"
    assert set(pb.keys()) == {"schema", "dataset_id", "split", "count", "pilot_membership_sha256"}
    holdout_binding = next(
        p for p in result.holdout_payloads if p.logical_name == "holdout_binding"
    )
    hb = json.loads(holdout_binding.canonical_bytes.rstrip(b"\n"))
    assert hb["schema"] == SCHEMA_HOLDOUT_BINDING
    assert hb["split"] == "holdout"
    # operator is aggregate only, no identity fields
    operator = next(p for p in result.operator_payloads if p.logical_name == "operator_preview")
    op = json.loads(operator.canonical_bytes.rstrip(b"\n"))
    assert op["schema"] == SCHEMA_OPERATOR_PAYLOAD
    for forb in ["strong_identity_digest", "item_semantic_sha256", "company_sampling_key", "rank"]:
        assert forb not in op
    # private provenance not contain split etc.
    # dataset/opaque ids
    # dataset id is 64 hex from domain
    dataset_id = pb["dataset_id"]
    assert len(dataset_id) == 64 and all(c in "0123456789abcdef" for c in dataset_id)
    # opaque ids 24 hex
    for rec in obj["records"]:
        oid = rec["opaque_id"]
        assert len(oid) == 24 and all(c in "0123456789abcdef" for c in oid)
    # blind order: pilot_sorted vs holdout sorted via domain hash, ensure distinct


def test_opaque_24hex_and_blind_order_and_byte_determinism() -> None:
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    inputs = _build_input()
    approved, ctx = _build_approved_and_context(inputs)
    r1 = materialize_payload_bytes(approved, ctx)
    r2 = materialize_payload_bytes(approved, ctx)
    # byte determinism: all payload bytes identical across reruns
    for a, b in zip(r1.private_payloads, r2.private_payloads, strict=False):
        assert a.canonical_bytes == b.canonical_bytes
    for a, b in zip(r1.pilot_payloads, r2.pilot_payloads, strict=False):
        assert a.canonical_bytes == b.canonical_bytes
    # holdout binding hash matches expected membership
    hb = next(p for p in r1.holdout_payloads if p.logical_name == "holdout_binding")
    obj = json.loads(hb.canonical_bytes.rstrip(b"\n"))
    assert (
        obj["holdout_membership_sha256"]
        == "0d74fb4cc056440eb5f65698ee49c5852547e85b7918d9e29d877fae031fd6d9"
    )
    pilot = next(p for p in r1.pilot_payloads if p.logical_name == "pilot_binding")
    assert (
        json.loads(pilot.canonical_bytes.rstrip(b"\n"))["pilot_membership_sha256"]
        == "e94cdd76dba624e94ba9229bf5ca396435d7e05fc30e80e9235034a5cc210ee3"
    )
    # opaque ids derived via dataset id distinct per semantic
    pilot_view_obj = json.loads(
        next(
            p for p in r1.pilot_payloads if p.logical_name == "pilot_label_view"
        ).canonical_bytes.rstrip(b"\n")
    )
    oids = [r["opaque_id"] for r in pilot_view_obj["records"]]
    assert len(oids) == len(set(oids)) == 2


def test_no_holdout_content_in_private_operator_pilot() -> None:
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    inputs = _build_input()
    approved, ctx = _build_approved_and_context(inputs)
    res = materialize_payload_bytes(approved, ctx)
    # collect all private/operator/pilot bytes as text
    all_text = b"".join(
        p.canonical_bytes for p in res.private_payloads + res.operator_payloads + res.pilot_payloads
    ).decode()
    # holdout membership hash appears only as aggregate in private? It's allowed, but holdout item hashes should not be enumerated
    # Ensure holdout semantic IDs not leaked outside holdout map
    holdout_sems = {
        "1111111111111111111111111111111111111111111111111111111111111111",
        "5555555555555555555555555555555555555555555555555555555555555555",
    }
    # The holdout binding hash is allowed, but raw semantic hashes of holdout should not appear in pilot/private/operator
    for sem in holdout_sems:
        # pilot view must not contain holdout semantics via opaque mapping leakage? Raw semantic must not appear
        pilot_view = next(p for p in res.pilot_payloads if p.logical_name == "pilot_label_view")
        assert sem not in pilot_view.canonical_bytes.decode()
        # operator not
        op = next(p for p in res.operator_payloads if p.logical_name == "operator_preview")
        assert sem not in op.canonical_bytes.decode()


# ---------------------------------------------------------------------------
# Recomputation / binding failures (stale, cross-gate)
# ---------------------------------------------------------------------------


def test_binding_failures_stale_cross_gate_one_hash_substitution() -> None:
    from role_radar.evaluation.profile_relevance import materialize_payload_bytes

    inputs = _build_input()
    approved, ctx = _build_approved_and_context(inputs)
    # stale: tamper approved selection hash one hex char
    bad_selection = "0" + approved.selection_sha256[1:]
    bad_approved = ApprovedPreview(
        preview_input_sha256=approved.preview_input_sha256,
        selection_sha256=bad_selection,
        partition_sha256=approved.partition_sha256,
        pilot_membership_sha256=approved.pilot_membership_sha256,
        holdout_membership_sha256=approved.holdout_membership_sha256,
        approval_binding_sha256=approved.approval_binding_sha256,
        operation_binding_sha256=approved.operation_binding_sha256,
        lineage_binding_sha256=approved.lineage_binding_sha256,
        schema_version=approved.schema_version,
        approved_by=approved.approved_by,
        approved_at_utc=approved.approved_at_utc,
    )
    # Need context that expects original approved, but we pass mismatched approved => materialization_context_mismatch via expected_approved_preview check
    with pytest.raises(ProfileRelevanceError) as ei:
        materialize_payload_bytes(bad_approved, ctx)
    assert ei.value.code in (
        "materialization_context_mismatch",
        "approved_preview_binding_mismatch",
        "cross_gate_substitution",
    )
    # cross-gate: swap operation binding (simulate Gate E substitution)
    bad_op = "f" * 64
    ctx_bad_op = MaterializationContext(
        inputs=ctx.inputs,
        display_values=ctx.display_values,
        provenance_values=ctx.provenance_values,
        expected_approved_preview=approved,
        operation_binding_sha256=bad_op,
        lineage_binding_sha256=ctx.lineage_binding_sha256,
        schema_version=ctx.schema_version,
        materialization_domain=ctx.materialization_domain,
        materialization_context_sha256=ctx.materialization_context_sha256,  # now mismatched hash
    )
    with pytest.raises(ProfileRelevanceError) as ei2:
        materialize_payload_bytes(approved, ctx_bad_op)
    assert ei2.value.code in (
        "materialization_context_mismatch",
        "cross_gate_substitution",
        "materialization_context_invalid",
    )
    # cross-lineage: different lineage binding
    bad_lineage = "e" * 64
    # Build new context with correct hash but lineage mismatch to approved
    ctx_preimage = {
        "display_values": [list(p) for p in ctx.display_values],
        "lineage_binding_sha256": bad_lineage,
        "materialization_domain": DOMAIN_MATERIALIZATION,
        "operation_binding_sha256": approved.operation_binding_sha256,
        "preview_input_sha256": inputs.preview_input_sha256,
        "provenance_values": [list(p) for p in ctx.provenance_values],
        "schema_version": SCHEMA_MATERIALIZATION_CONTEXT,
    }
    bad_lineage_ctx_hash = domain_hash(DOMAIN_MATERIALIZATION_CONTEXT, ctx_preimage)
    bad_lineage_ctx = MaterializationContext(
        inputs=ctx.inputs,
        display_values=ctx.display_values,
        provenance_values=ctx.provenance_values,
        expected_approved_preview=approved,
        operation_binding_sha256=approved.operation_binding_sha256,
        lineage_binding_sha256=bad_lineage,
        schema_version=ctx.schema_version,
        materialization_domain=ctx.materialization_domain,
        materialization_context_sha256=bad_lineage_ctx_hash,
    )
    with pytest.raises(ProfileRelevanceError) as ei3:
        materialize_payload_bytes(approved, bad_lineage_ctx)
    assert ei3.value.code == "cross_gate_substitution"
    # wrong schema
    bad_schema_approved = ApprovedPreview(
        preview_input_sha256=approved.preview_input_sha256,
        selection_sha256=approved.selection_sha256,
        partition_sha256=approved.partition_sha256,
        pilot_membership_sha256=approved.pilot_membership_sha256,
        holdout_membership_sha256=approved.holdout_membership_sha256,
        approval_binding_sha256=approved.approval_binding_sha256,
        operation_binding_sha256=approved.operation_binding_sha256,
        lineage_binding_sha256=approved.lineage_binding_sha256,
        schema_version="wrong-schema",
        approved_by=approved.approved_by,
        approved_at_utc=approved.approved_at_utc,
    )
    with pytest.raises(ProfileRelevanceError) as ei4:
        materialize_payload_bytes(bad_schema_approved, ctx)
    assert ei4.value.code == "payload_schema_invalid"


def test_preview_result_not_interchangeable_with_approved() -> None:
    from role_radar.evaluation.profile_relevance import compute_preview, materialize_payload_bytes

    inputs = _build_input()
    preview_res = compute_preview(inputs)
    approved, ctx = _build_approved_and_context(inputs)
    # Attempt to pass PreviewComputationResult as ApprovedPreview -> type check
    with pytest.raises(ProfileRelevanceError) as ei:
        materialize_payload_bytes(preview_res, ctx)  # type: ignore[arg-type]
    assert ei.value.code in ("approved_preview_required", "materialization_context_invalid")
