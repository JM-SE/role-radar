"""Focused offline transition coverage for the amended F10.1F seam."""

from __future__ import annotations

import pytest

from role_radar.evaluation.profile_relevant_acquisition.challenge_loader import (
    ChallengeLoadError,
    build_challenge_bytes,
    load_challenge_bytes,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ArtifactClass,
    ChallengeArtifact,
    ExternalApprovalBinding,
    OperationalContractError,
    ProvenanceArtifact,
    SourcePlanBinding,
    require_execution_boundary,
    synthetic_test_adapter,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_runtime import (
    GateCError,
    run_gate_c_runtime,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_runtime import run_gate_d_runtime
from role_radar.evaluation.profile_relevant_acquisition.gate_e_runtime import run_gate_e_runtime
from role_radar.evaluation.profile_relevant_acquisition.gate_f_runtime import run_gate_f_runtime
from role_radar.evaluation.profile_relevant_acquisition.policy import (
    PolicyError,
    validate_quota_totals,
    validate_seed_pair,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_runtime import (
    run_post_c_preregistration_runtime,
)
from role_radar.evaluation.profile_relevant_acquisition.provenance_loader import (
    build_provenance_bytes,
    load_provenance_bytes,
)
from tests.unit.test_profile_relevance_materialization import _build_input

SELECTION = "a" * 64
PARTITION = "b" * 64
HASH = "c" * 64


def _artifacts(gate: str) -> tuple[ChallengeArtifact, ProvenanceArtifact]:
    provenance = load_provenance_bytes(
        build_provenance_bytes(
            operation_id="op",
            lineage_id="lineage",
            commit_sha256=HASH,
            window_sha256=HASH,
            namespace_sha256=HASH,
            policy_sha256=HASH,
            artifact_class=ArtifactClass.SYNTHETIC,
            selection_seed=SELECTION,
            partition_seed=PARTITION,
        )
    )
    challenge = load_challenge_bytes(
        build_challenge_bytes(
            gate=gate,
            operation_id="op",
            lineage_id="lineage",
            artifact_class=ArtifactClass.SYNTHETIC,
            selection_seed=SELECTION,
            partition_seed=PARTITION,
            policy_sha256=HASH,
            payload_sha256=HASH,
        ),
        expected_gate=gate,
    )
    return challenge, provenance


def test_loaders_are_canonical_and_hash_bound() -> None:
    raw = build_challenge_bytes(
        gate="C",
        operation_id="op",
        lineage_id="lineage",
        artifact_class=ArtifactClass.SYNTHETIC,
        selection_seed=SELECTION,
        partition_seed=PARTITION,
        policy_sha256=HASH,
        payload_sha256=HASH,
    )
    assert load_challenge_bytes(raw, expected_gate="C").gate == "C"
    tampered = raw.replace(
        b'"payload_sha256":"' + HASH.encode(),
        b'"payload_sha256":"' + b"d" * 64,
    )
    with pytest.raises(ChallengeLoadError) as exc:
        load_challenge_bytes(tampered, expected_gate="C")
    assert exc.value.code == "challenge_hash_mismatch"


def test_artifact_dtos_reject_forged_canonical_bytes_at_constructor() -> None:
    challenge, provenance = _artifacts("C")
    with pytest.raises(OperationalContractError) as challenge_error:
        type(challenge)(
            challenge.schema_version,
            challenge.gate,
            challenge.operation_id,
            challenge.lineage_id,
            challenge.prerequisite_status,
            challenge.artifact_class,
            challenge.seed_inputs,
            challenge.policy_sha256,
            challenge.payload_sha256,
            challenge.challenge_sha256,
            b"{}",
        )
    assert challenge_error.value.code == "canonical_record_invalid"

    with pytest.raises(OperationalContractError) as provenance_error:
        type(provenance)(
            provenance.schema_version,
            provenance.operation_id,
            provenance.lineage_id,
            provenance.commit_sha256,
            provenance.window_sha256,
            provenance.namespace_sha256,
            provenance.policy_sha256,
            provenance.artifact_class,
            provenance.seed_inputs,
            provenance.provenance_sha256,
            b"{}",
        )
    assert provenance_error.value.code == "canonical_record_invalid"


@pytest.mark.parametrize(
    ("selection", "partition"),
    (
        ("a" * 63, PARTITION),
        ("A" * 64, PARTITION),
        (SELECTION, SELECTION),
        (SELECTION, "b" * 65),
    ),
)
def test_seed_boundaries_block_before_any_runtime(selection: str, partition: str) -> None:
    with pytest.raises(PolicyError):
        validate_seed_pair(selection, partition)


def test_quota_cap_applies_to_every_board() -> None:
    validate_quota_totals({"board-a": 2, "board-b": 4}, per_board_cap=4)
    with pytest.raises(PolicyError) as exc:
        validate_quota_totals({"board-a": 2, "board-b": 5}, per_board_cap=4)
    assert exc.value.code == "quota_exceeds_per_board_cap"


def test_valid_synthetic_local_runtimes_call_once_and_stop() -> None:
    calls: list[str] = []
    challenge, provenance = _artifacts("C")
    result = run_gate_c_runtime(
        challenge=challenge,
        provenance=provenance,
        delegate=lambda: calls.append("C"),
        test_only_adapter=synthetic_test_adapter(),
    )
    assert calls == ["C"]
    assert result.stopped

    challenge, provenance = _artifacts("post-C")
    run_post_c_preregistration_runtime(
        challenge=challenge,
        provenance=provenance,
        seeds=provenance.seed_inputs,
        source_plan=SourcePlanBinding(
            operation_id="op",
            lineage_id="lineage",
            policy_sha256=HASH,
            source_plan_sha256=HASH,
            artifact_class=ArtifactClass.SYNTHETIC,
            prerequisite_status="passed",
        ),
        delegate=lambda: calls.append("post-C"),
        test_only_adapter=synthetic_test_adapter(),
    )
    challenge, provenance = _artifacts("D")
    run_gate_d_runtime(
        challenge=challenge,
        provenance=provenance,
        delegate=lambda: calls.append("D"),
        test_only_adapter=synthetic_test_adapter(),
    )
    challenge, provenance = _artifacts("E")
    run_gate_e_runtime(
        challenge=challenge,
        provenance=provenance,
        inputs=_build_input(),
        test_only_adapter=synthetic_test_adapter(),
    )
    challenge, provenance = _artifacts("F")
    run_gate_f_runtime(
        challenge=challenge,
        provenance=provenance,
        materializer=lambda: calls.append("F"),
        test_only_adapter=synthetic_test_adapter(),
    )
    assert calls == ["C", "post-C", "D", "F"]


def test_invalid_artifact_or_production_dependency_never_delegates() -> None:
    challenge, provenance = _artifacts("D")
    calls: list[str] = []
    with pytest.raises(GateCError) as exc:
        run_gate_c_runtime(
            challenge=challenge,
            provenance=provenance,
            delegate=lambda: calls.append("called"),
            test_only_adapter=synthetic_test_adapter(),
        )
    assert exc.value.code == "gate_c_wrong_challenge"
    assert calls == []


def test_post_c_policy_binding_mismatch_never_delegates() -> None:
    _challenge, provenance = _artifacts("post-C")
    calls: list[str] = []
    with pytest.raises(ValueError) as exc:
        type(provenance)(
            provenance.schema_version,
            provenance.operation_id,
            provenance.lineage_id,
            provenance.commit_sha256,
            provenance.window_sha256,
            provenance.namespace_sha256,
            "d" * 64,
            provenance.artifact_class,
            provenance.seed_inputs,
            provenance.provenance_sha256,
            provenance.canonical_bytes,
        )
    assert getattr(exc.value, "code", "") == "provenance_hash_mismatch"
    assert calls == []


def test_gate_f_forbidden_callable_never_runs() -> None:
    challenge, provenance = _artifacts("F")
    calls: list[str] = []

    class ForbiddenCallable:
        execute = object()

        def __call__(self) -> None:
            calls.append("called")

    with pytest.raises(ValueError) as exc:
        run_gate_f_runtime(
            challenge=challenge,
            provenance=provenance,
            materializer=ForbiddenCallable(),
            test_only_adapter=synthetic_test_adapter(),
        )
    assert getattr(exc.value, "code", "") == "gate_f_production_dependency_forbidden"
    assert calls == []


def test_builders_cannot_self_label_approved_production() -> None:
    with pytest.raises(ChallengeLoadError) as challenge_error:
        build_challenge_bytes(
            gate="C",
            operation_id="op",
            lineage_id="lineage",
            artifact_class=ArtifactClass.APPROVED_PRODUCTION,
            selection_seed=SELECTION,
            partition_seed=PARTITION,
            policy_sha256=HASH,
            payload_sha256=HASH,
        )
    assert challenge_error.value.code == "challenge_approved_class_builder_forbidden"

    from role_radar.evaluation.profile_relevant_acquisition.provenance_loader import (
        ProvenanceLoadError,
        build_provenance_bytes,
    )

    with pytest.raises(ProvenanceLoadError) as provenance_error:
        build_provenance_bytes(
            operation_id="op",
            lineage_id="lineage",
            commit_sha256=HASH,
            window_sha256=HASH,
            namespace_sha256=HASH,
            policy_sha256=HASH,
            artifact_class=ArtifactClass.APPROVED_PRODUCTION,
            selection_seed=SELECTION,
            partition_seed=PARTITION,
        )
    assert provenance_error.value.code == "provenance_approved_class_builder_forbidden"


def test_approved_execution_requires_injected_external_verifier() -> None:
    approval = ExternalApprovalBinding(
        artifact_sha256=HASH,
        approval_binding_sha256=SELECTION,
        issuer="external-approver",
        opaque_token=b"external-token-0123",
    )
    with pytest.raises(ValueError):
        require_execution_boundary(
            artifact_sha256=HASH,
            test_only_adapter=None,
            approval=approval,
            approval_verifier=None,
            code="approval_required",
        )

    require_execution_boundary(
        artifact_sha256=HASH,
        test_only_adapter=None,
        approval=approval,
        approval_verifier=lambda value, digest: value is approval and digest == HASH,
        code="approval_required",
    )
