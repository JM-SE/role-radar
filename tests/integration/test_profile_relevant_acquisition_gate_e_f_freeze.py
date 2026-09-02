"""Offline Gate E/F and F10.1F freeze transaction coverage."""

# The cross-gate fixture is intentionally explicit; keep its long binding rows readable.
# ruff: noqa: E501, RUF005

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from role_radar.evaluation.profile_relevance.contracts import (
    CanonicalPayload,
    ProfileRelevanceInput,
)
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    GateDResult,
    ParentPoolManifest,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    build_f_handoff,
    synthetic_test_adapter,
)
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import (
    DIRNAME_OPERATOR,
    DIRNAME_PILOT,
    DIRNAME_PRIVATE,
    DIRNAME_SEALED_HOLDOUT,
    FreezeBindings,
    FreezeError,
    run_freeze_transaction,
    verify_frozen_publication,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    GateEAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_preview import (
    run_gate_e_preview,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_authorization import (
    GateFAuthorization,
    GateFAuthorizationRequest,
    freeze_bindings_for_request,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_materialization import (
    GateFError,
    run_gate_f_materialization,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_service import (
    run_gate_f_materialization_freeze,
)
from role_radar.evaluation.profile_relevant_acquisition.provenance import (
    build_provenance_bundle,
)
from tests.unit.test_profile_relevance_materialization import (
    _build_approved_and_context,
    _build_input,
)
from tests.unit.test_profile_relevant_acquisition_provenance_store_report import _provenance
from tests.unit.test_profile_relevant_gate_d_bounded_acquisition import _request as _gate_d_request


def _real_service_request(root: Path) -> GateFAuthorizationRequest:
    """Assemble the exact cross-gate graph from the existing synthetic fixtures."""
    d_request = _gate_d_request(root)
    inputs = _live_namespace_input()
    inputs = replace(inputs, sealed_snapshot=replace(inputs.sealed_snapshot, namespace=d_request.post_c_request.source_plan.namespace, source_plan_sha256=d_request.post_c_request.source_plan.source_plan_sha256))
    from role_radar.evaluation.profile_relevance.hashing import (
        canonical_json_bytes,
        domain_hash_bytes,
    )
    from role_radar.evaluation.profile_relevance.policy import (
        DOMAIN_PARTITION_POLICY,
        DOMAIN_SAMPLING_POLICY,
    )
    extra = tuple(replace(inputs.sealed_snapshot.observations[0], observation_id=f"obs-extra-{i}", item_semantic_sha256=("9" if i == 0 else "a") * 64, strong_identity_digest=("0" if i == 0 else "1") * 64) for i in range(2))
    observations = inputs.sealed_snapshot.observations + extra
    quotas = (replace(inputs.sampling_policy.quotas[0], corpus_quota=10),) + inputs.sampling_policy.quotas[1:]
    sampling_raw = {"corpus": 10, "seed": inputs.sampling_policy.selection_seed, "quotas": [[q.source_unit, q.stratum, q.corpus_quota] for q in quotas]}
    sampling = replace(inputs.sampling_policy, corpus_cardinality=10, per_board_cap=10, global_per_company_cap=10, quotas=quotas, sampling_policy_sha256=domain_hash_bytes(DOMAIN_SAMPLING_POLICY, canonical_json_bytes(sampling_raw)), canonical_bytes=canonical_json_bytes(sampling_raw))
    partition_quotas = (replace(inputs.partition_policy.pilot_quotas[0], pilot_quota=2),) + inputs.partition_policy.pilot_quotas[1:]
    partition_raw = {"pilot": 2, "total": 10, "seed": inputs.partition_policy.partition_seed, "pilot_quotas": [[q.source_unit, q.stratum, q.pilot_quota] for q in partition_quotas]}
    partition_raw["sampling_policy_sha256"] = sampling.sampling_policy_sha256
    partition_hash = domain_hash_bytes(DOMAIN_PARTITION_POLICY, canonical_json_bytes(partition_raw))
    partition = replace(inputs.partition_policy, total_count=10, holdout_count=8, pilot_quotas=partition_quotas, sampling_policy_sha256=sampling.sampling_policy_sha256, partition_policy_sha256=partition_hash, canonical_bytes=canonical_json_bytes(partition_raw))
    inputs = replace(inputs, sealed_snapshot=replace(inputs.sealed_snapshot, observations=observations), sampling_policy=sampling, partition_policy=partition)
    sealed = tuple(
        replace(
            observation,
            canonical_observation_bytes=json.dumps(
                {"description": observation.description, "external_id": observation.observation_id,
                 "location": observation.location, "source_id": observation.source.source_id,
                 "source_key": observation.source.board_key, "title": observation.title},
                sort_keys=True, separators=(",", ":"),
            ).encode(),
        )
        for observation in inputs.sealed_snapshot.observations
    )
    inputs = replace(inputs, sealed_snapshot=replace(inputs.sealed_snapshot, observations=sealed))
    post = d_request.post_c_request
    post_seal = __import__(
        "role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts",
        fromlist=["build_seal"],
    ).build_seal(post)
    d_request = replace(d_request, post_c_request=post, post_c_seal=post_seal)
    base = _provenance(root=str(root), relevance_policy_sha256=inputs.relevance_policy.policy_sha256, selection_seed=inputs.sampling_policy.selection_seed, partition_seed=inputs.partition_policy.partition_seed)
    provenance = build_provenance_bundle(
        commit_sha=base.commit_sha, diff_sha256=base.diff_sha256, status_sha256=base.status_sha256,
        lock_sha256=base.lock_sha256, alembic_head=base.alembic_head,
        profile_binding_sha256=base.profile_binding_sha256, discovery_policy_sha256=base.discovery_policy_sha256,
        relevance_policy_sha256=inputs.relevance_policy.policy_sha256, display_contract_sha256=base.display_contract_sha256,
        planner_sha256=base.planner_sha256, query_plan_sha256=post.query_plan.plan_sha256,
        sampling_formula_sha256=base.sampling_formula_sha256, partition_formula_sha256=base.partition_formula_sha256,
        window_start_utc=base.window_start_utc, window_end_utc=base.window_end_utc, cutoff_utc=base.cutoff_utc,
        inventory_sha256=base.inventory_sha256, old_artifact_hashes=dict(base.old_artifact_hashes),
        selection_seed=inputs.sampling_policy.selection_seed, partition_seed=inputs.partition_policy.partition_seed,
        per_board_cap=inputs.sampling_policy.per_board_cap, per_company_cap=inputs.sampling_policy.global_per_company_cap,
        corpus_total=10, pilot_count=2, holdout_count=8, namespace=inputs.sealed_snapshot.namespace, root=str(root),
    )
    result, record = run_gate_e_preview(inputs=inputs, provenance=provenance)
    observations = inputs.sealed_snapshot.observations
    from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
        ObservationEnvelope,
    )
    envelopes = tuple(
        ObservationEnvelope(
            o.source.source_id, o.source.board_key, 1, 1, o.observation_id, o.title,
            o.company_sampling_key, o.location, o.description, None, o.canonical_observation_bytes,
            __import__("hashlib").sha256(o.canonical_observation_bytes).hexdigest(),
        ) for o in observations
    )
    pool_sha = __import__("hashlib").sha256(json.dumps(sorted(e.canonical_sha256 for e in envelopes), separators=(",", ":")).encode()).hexdigest()
    manifest_payload = {
        "operation_id": d_request.operation_id, "source_plan_sha256": post.source_plan.source_plan_sha256,
        "preregistration_sha256": post_seal.preregistration_sha256, "provenance_sha256": post.provenance.gate_b_packet_sha256,
        "observed": len(observations), "new_to_pool": len(observations), "duplicate": 0, "stale": 0, "invalid": 0,
        "conflict": 0, "truncated": 0, "indeterminate": 0, "durable_intents": 0, "known_terminal_outcomes": 0,
        "pending_or_indeterminate": 0, "delegate_entries": 0, "budget_debits": 0, "collector_wire_attempts": 0,
        "budget_consumed": 0, "checkpoint_wire_attempts": 0, "pool_sha256": pool_sha,
    }
    manifest = ParentPoolManifest(**manifest_payload, canonical_bytes=json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")).encode())
    gate_d = GateDResult(d_request.operation_id, 0, 0, (), pool_sha, manifest, envelopes)
    gate_e = GateEAuthorizationRequest(d_request.operation_id, d_request.lineage_id, d_request, gate_d, manifest, post, post_seal, provenance, d_request.current_commit_sha256, inputs)
    context = _build_approved_and_context(inputs)[1]
    preview_payloads = run_gate_f_materialization(
        approved_preview=context.expected_approved_preview,
        materialization_context=context,
        test_only_adapter=synthetic_test_adapter(),
    )
    dataset_id = str(json.loads(next(p for p in preview_payloads.operator_payloads if p.logical_name == "operator_preview").canonical_bytes)["dataset_id"])
    return GateFAuthorizationRequest(GateFAuthorization(d_request.operation_id, d_request.lineage_id, "a" * 64, "2099-01-01T00:00:00Z", "synthetic", synthetic_test_adapter()), gate_e, gate_d, manifest, provenance, inputs, record, result, context, dataset_id, root)


def test_real_gate_f_service_materializes_freezes_and_hands_off_exactly(tmp_path: Path) -> None:
    from unittest.mock import Mock

    from role_radar.evaluation.profile_relevant_acquisition.contracts import F10_1FHandoff
    from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import (
        run_freeze_transaction,
    )
    from role_radar.evaluation.profile_relevant_acquisition.gate_f_materialization import (
        run_gate_f_materialization,
    )

    request = _real_service_request(tmp_path / "isolated")
    materializer = Mock(wraps=run_gate_f_materialization)
    freezer = Mock(wraps=run_freeze_transaction)
    result = run_gate_f_materialization_freeze(
        request=request,
        freeze_bindings=freeze_bindings_for_request(request),
        clock=lambda: datetime(2026, 8, 25, 2, 30, tzinfo=UTC),
        materializer=materializer,
        freezer=freezer,
    )
    assert materializer.call_count == freezer.call_count == 1
    handoff = freezer.call_args.kwargs["f_handoff"]
    assert isinstance(handoff, F10_1FHandoff)
    assert handoff.payloads == freezer.call_args.kwargs["f_handoff"].payloads
    assert result.public.as_dict()["status"] == "completed"
    assert result.public.as_dict()["code"] == "gate_f_materialization_freeze_completed"
    assert result.public.as_dict()["preview_input_sha256"] == request.profile_relevance_input.preview_input_sha256
    assert not {"root", "path", "payload", "title", "description"} & set(result.public.as_dict())
    assert not any((tmp_path / "isolated").glob("**/successor"))


def test_real_gate_f_exact_replay_verifies_generated_publication_without_effects(tmp_path: Path) -> None:
    from unittest.mock import Mock

    from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import (
        run_freeze_transaction,
    )
    from role_radar.evaluation.profile_relevant_acquisition.gate_f_materialization import (
        run_gate_f_materialization,
    )

    request = _real_service_request(tmp_path / "isolated")
    bindings = freeze_bindings_for_request(request)
    captured: dict[str, object] = {}
    materializer_first = Mock(side_effect=lambda **kwargs: captured.setdefault("payloads", run_gate_f_materialization(**kwargs)))
    freezer_first = Mock(side_effect=lambda **kwargs: captured.setdefault("benchmark", run_freeze_transaction(**kwargs)))
    first = run_gate_f_materialization_freeze(request=request, freeze_bindings=bindings, clock=lambda: datetime(2026, 8, 25, 2, 30, tzinfo=UTC), materializer=materializer_first, freezer=freezer_first)
    materializer = Mock(wraps=run_gate_f_materialization)
    freezer = Mock(wraps=run_freeze_transaction)
    replay = run_gate_f_materialization_freeze(request=request, freeze_bindings=bindings, clock=lambda: datetime(2026, 8, 25, 2, 30, tzinfo=UTC), materializer=materializer, freezer=freezer)
    assert replay.public.code == "gate_f_materialization_freeze_replayed"
    assert replay.public.as_dict() == {**first.public.as_dict(), "code": "gate_f_materialization_freeze_replayed"}
    assert materializer.call_count == freezer.call_count == 0
    dataset = request.destination_root / request.dataset_id
    assert verify_frozen_publication(
        root=request.destination_root,
        benchmark=captured["benchmark"],
        payloads=captured["payloads"],
        test_only_adapter=request.authorization.test_only_adapter,
    )
    assert all((dataset / name).is_file() for name in ("manifest.json", "sealed_pool_manifest.json", "checksums.sha256", "receipt.json"))


def _live_namespace_input() -> ProfileRelevanceInput:
    base = _build_input()
    return replace(
        base, sealed_snapshot=replace(base.sealed_snapshot, namespace="synthetic-f10-1f")
    )


def test_gate_e_runs_only_sanitized_preview_with_no_materialization_bytes() -> None:
    inputs = _live_namespace_input()
    provenance = _provenance(
        relevance_policy_sha256=inputs.relevance_policy.policy_sha256,
        selection_seed=inputs.sampling_policy.selection_seed,
        partition_seed=inputs.partition_policy.partition_seed,
    )

    result, record = run_gate_e_preview(inputs=inputs, provenance=provenance)

    assert result.sanitized_preview.canonical_payload.endswith(b"\n")
    assert b"title" not in result.sanitized_preview.canonical_payload
    assert b"description" not in result.sanitized_preview.canonical_payload
    assert record.provenance_sha256 == provenance.provenance_sha256
    assert b"holdout_membership_sha256" in record.canonical_bytes


def test_gate_f_materializes_only_exact_approved_context_bindings() -> None:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)

    payloads = run_gate_f_materialization(
        approved_preview=approved,
        materialization_context=context,
        test_only_adapter=synthetic_test_adapter(),
    )
    assert len(payloads.private_payloads) == 6
    assert len(payloads.operator_payloads) == 1
    assert len(payloads.pilot_payloads) == 2
    assert {item.logical_name for item in payloads.holdout_payloads} == {
        "holdout_binding",
        "holdout_sealed_view",
    }

    with pytest.raises(GateFError) as mismatch:
        run_gate_f_materialization(
            approved_preview=approved,
            materialization_context=replace(
                context,
                operation_binding_sha256="f" * 64,
            ),
            test_only_adapter=synthetic_test_adapter(),
        )
    assert mismatch.value.code == "gate_f_cross_gate_substitution"


def test_gate_f_legacy_materializer_requires_explicit_test_boundary() -> None:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)
    with pytest.raises(GateFError) as blocked:
        run_gate_f_materialization(
            approved_preview=approved,
            materialization_context=context,
        )
    assert blocked.value.code == "gate_f_execution_authorization_required"


def _payload_object(group: tuple[CanonicalPayload, ...], name: str) -> dict[str, object]:
    payload = next(item for item in group if item.logical_name == name)
    return cast(dict[str, object], json.loads(payload.canonical_bytes.rstrip(b"\n")))


def _int_field(value: dict[str, object], key: str) -> int:
    field = value[key]
    assert isinstance(field, int)
    return field


def test_freeze_publishes_manifest_capabilities_and_receipt_once(tmp_path: Path) -> None:
    inputs = _build_input()
    approved, context = _build_approved_and_context(inputs)
    payloads = run_gate_f_materialization(
        approved_preview=approved,
        materialization_context=context,
        test_only_adapter=synthetic_test_adapter(),
    )
    root = tmp_path / "f10-1f"
    provenance = _provenance(root=str(root))

    operator = _payload_object(payloads.operator_payloads, "operator_preview")
    population = _payload_object(payloads.private_payloads, "population")
    pilot = _payload_object(payloads.pilot_payloads, "pilot_binding")
    holdout = _payload_object(payloads.holdout_payloads, "holdout_binding")
    bindings = FreezeBindings(
        dataset_id=str(operator["dataset_id"]),
        pool_sha256="1" * 64,
        provenance_sha256=provenance.provenance_sha256,
        f_challenge_sha256="a" * 64,
        inventory_sha256=provenance.inventory_sha256,
        source_plan_sha256=inputs.sealed_snapshot.source_plan_sha256,
        preview_input_sha256=str(operator["preview_input_sha256"]),
        selection_sha256=str(operator["selection_sha256"]),
        partition_sha256=approved.partition_sha256,
        pilot_membership_sha256=str(pilot["pilot_membership_sha256"]),
        holdout_membership_sha256=str(holdout["holdout_membership_sha256"]),
        observation_count=_int_field(population, "observation_count"),
        corpus_count=_int_field(operator, "corpus_count"),
        pilot_count=_int_field(operator, "pilot_count"),
        holdout_count=_int_field(operator, "holdout_count"),
        per_board_cap=4,
        per_company_cap=2,
        namespace="synthetic-f10-1f",
        root=str(root),
    )

    f_handoff = build_f_handoff(
        operation_id="freeze-op",
        challenge_sha256="a" * 64,
        provenance_sha256=provenance.provenance_sha256,
        artifact_class=ArtifactClass.SYNTHETIC,
        payloads=payloads,
    )
    benchmark = run_freeze_transaction(
        root=root,
        bindings=bindings,
        f_handoff=f_handoff,
        provenance=provenance,
        test_only_adapter=synthetic_test_adapter(),
    )
    assert benchmark.verified
    assert benchmark.receipt.transaction_complete
    assert set(benchmark.capability_kinds) == {"private", "pilot", "sealed_holdout"}
    assert verify_frozen_publication(
        root=root,
        benchmark=benchmark,
        payloads=payloads,
        test_only_adapter=synthetic_test_adapter(),
    )

    dataset = root / benchmark.dataset_id
    assert (dataset / "manifest.json").is_file()
    assert (dataset / "sealed_pool_manifest.json").is_file()
    assert (dataset / "checksums.sha256").is_file()
    assert (dataset / "receipt.json").is_file()
    assert {item.name for item in (dataset / "capabilities").iterdir()} == {
        "private.json",
        "pilot.json",
        "sealed_holdout.json",
    }
    assert {item.name for item in (dataset / DIRNAME_PRIVATE).iterdir()} == {
        "gate_decisions.json",
        "population.json",
        "preview.json",
        "provenance.json",
        "sampling_cells.json",
        "selection.json",
    }
    assert (dataset / DIRNAME_OPERATOR / "operator_preview.json").is_file()
    assert (dataset / DIRNAME_PILOT / "pilot_binding.json").is_file()
    assert (dataset / DIRNAME_SEALED_HOLDOUT / "holdout_binding.json").is_file()

    receipt = json.loads((dataset / "receipt.json").read_bytes())
    assert receipt["transaction_complete"] is True
    assert not any(key in receipt for key in ("title", "company", "description", "url", "source"))
    assert not (tmp_path / "snapshot").exists()
    assert not (tmp_path / "f10.1").exists()
    assert not (tmp_path / "holdout").exists()

    rerun = run_freeze_transaction(
        root=root,
        bindings=bindings,
        f_handoff=f_handoff,
        provenance=provenance,
        test_only_adapter=synthetic_test_adapter(),
    )
    assert rerun.receipt.canonical_bytes == benchmark.receipt.canonical_bytes
    assert verify_frozen_publication(
        root=root,
        benchmark=rerun,
        payloads=payloads,
        test_only_adapter=synthetic_test_adapter(),
    )


def test_freeze_legacy_publication_requires_explicit_boundary(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as blocked:
        run_freeze_transaction(
            root=tmp_path / "f10-1f",
            bindings=object(),  # type: ignore[arg-type]
            provenance=object(),  # type: ignore[arg-type]
        )
    assert getattr(blocked.value, "code", "") == "freeze_execution_authorization_required"


def test_freeze_rejects_materialized_payloads_without_f_handoff(tmp_path: Path) -> None:
    with pytest.raises(FreezeError) as blocked:
        run_freeze_transaction(
            root=tmp_path / "f10-1f",
            bindings=object(),  # type: ignore[arg-type]
            provenance=object(),  # type: ignore[arg-type]
            test_only_adapter=synthetic_test_adapter(),
        )
    assert blocked.value.code == "freeze_f_handoff_required"
