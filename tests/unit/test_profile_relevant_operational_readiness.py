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
    ProvenanceArtifact,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_runtime import (
    GateCError,
    run_gate_c_runtime,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_runtime import run_gate_d_runtime
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
        offline_harness=True,
    )
    assert calls == ["C"]
    assert result.stopped

    challenge, provenance = _artifacts("post-C")
    run_post_c_preregistration_runtime(
        challenge=challenge,
        provenance=provenance,
        seeds=provenance.seed_inputs,
        delegate=lambda: calls.append("post-C"),
        offline_harness=True,
    )
    challenge, provenance = _artifacts("D")
    run_gate_d_runtime(
        challenge=challenge,
        provenance=provenance,
        delegate=lambda: calls.append("D"),
        offline_harness=True,
    )
    challenge, provenance = _artifacts("F")
    run_gate_f_runtime(
        challenge=challenge,
        provenance=provenance,
        materializer=lambda: calls.append("F"),
        offline_harness=True,
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
            offline_harness=True,
        )
    assert exc.value.code == "gate_c_wrong_challenge"
    assert calls == []
