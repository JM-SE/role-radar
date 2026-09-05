"""Production verifier: file-anchored packet checks, fake everything else.

No live network, no real credentials. Temporary packet/history roots only,
under both network-denial forms via the suite runner.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from role_radar.discovery.planner_v2 import plan_profile_discovery
from role_radar.discovery.policy import (
    DiscoveryPhraseGrammarV1,
    DiscoveryPolicyV1,
    policy_sha256,
)
from role_radar.discovery.profile_terms import (
    CompiledDiscoveryPhraseV1,
    CompiledDiscoveryTermsV1,
    DiscoveryTermProvenanceV1,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    PreflightReport,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    GATE_C_AUTH_SCHEMA,
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCProvenance,
    gate_b_packet_sha256,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_capability import (
    RealDiscoveryVerification,
    capability_from_independent_verifier,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_verifier import (
    IndependentPacketVerifier,
    RealDiscoveryVerifierError,
)

NOW = datetime(2026, 9, 10, 1, tzinfo=UTC)
OPERATION_ID = "33333333-3333-4333-8333-333333333333"
LINEAGE_ID = "44444444-4444-4444-8444-444444444444"
APPROVAL_REF = "operator-approval-test-only"
GIT_HEAD = "ab" * 20
SELECTION = "a1" * 32
PARTITION = "b2" * 32


def _packet(root: Path) -> GateBPacket:
    commit = hashlib.sha256(GIT_HEAD.encode("ascii")).hexdigest()
    return GateBPacket(
        code_commit_sha256=commit,
        namespace="r2-verifier-test",
        root=str(root),
        selection_seed=SELECTION,
        partition_seed=PARTITION,
        seed_origin="operator_supplied",
        seed_generated=False,
        profile_id="00000000-0000-0000-0000-000000000001",
        profile_version="1",
        profile_sha256="c" * 64,
        policy_id="policy-v1",
        policy_version="1",
        policy_sha256="c" * 64,
        window_start_utc="2026-09-10T00:00:00Z",
        window_end_utc="2026-09-11T00:00:00Z",
        per_board_cap=4,
        per_company_cap=2,
        corpus_count=10,
        pilot_count=2,
        holdout_count=8,
        budget_units=20,
        historical_reference=False,
        authority_reference="new_planned_packet",
    )


def _plan() -> Any:
    policy = DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": "1",
            "profile_binding": {
                "profile_id": "00000000-0000-0000-0000-000000000001",
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": "c" * 64,
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {"primary": ["Backend Engineer"]},
            "target_roles": {"backend": {"primary_groups": ["primary"]}},
            "target_titles": {},
        }
    )
    terms = CompiledDiscoveryTermsV1(
        profile_binding=policy.profile_binding,
        policy_version=policy.policy_version,
        policy_sha256=policy_sha256(policy),
        phrases=(
            CompiledDiscoveryPhraseV1(
                "Backend Engineer",
                (DiscoveryTermProvenanceV1("target_roles", "backend", "primary", False),),
            ),
        ),
    )
    return plan_profile_discovery(terms, policy)


def _config(paid: bool = False) -> Any:
    quota = lambda handle: SimpleNamespace(  # noqa: E731
        enabled=True, units_limit=4, credential_handle=handle
    )
    namespace: dict[str, Any] = {
        "config_version": "config-v1",
        "brave_free": quota("brave-free"),
        "tavily_free": quota("tavily-free"),
    }
    if paid:
        namespace["brave_paid"] = SimpleNamespace(enabled=True)
    return SimpleNamespace(**namespace)


def _bundle(tmp_path: Path) -> tuple[Any, Any, Any, Any]:
    plan = _plan()
    packet = dataclasses.replace(_packet(tmp_path), policy_sha256=plan.policy_sha256)
    packet_hash = gate_b_packet_sha256(packet)
    accepted = AcceptedGateBBinding(
        packet,
        packet_hash,
        PreflightReport(
            result="ready",
            code="gate_b_packet_ready",
            code_commit_sha256=packet.code_commit_sha256,
            profile_sha256=packet.profile_sha256,
            policy_sha256=packet.policy_sha256,
            packet_sha256=packet_hash,
        ),
    )
    authorization = GateCAuthorization(
        gate="C",
        mode="report-only",
        report_only=True,
        operation_id=OPERATION_ID,
        lineage_id=LINEAGE_ID,
        expires_at_utc="2026-09-10T06:00:00Z",
        provenance=GateCProvenance(
            gate_b_packet_sha256=packet_hash,
            candidate_commit_sha256=packet.code_commit_sha256,
            profile_id=packet.profile_id,
            profile_version=packet.profile_version,
            profile_sha256=packet.profile_sha256,
            policy_id=packet.policy_id,
            policy_version=packet.policy_version,
            policy_sha256=packet.policy_sha256,
            query_plan_sha256=plan.plan_sha256,
            namespace=packet.namespace,
            approved_root=packet.root,
            window_start_utc=packet.window_start_utc,
            window_end_utc=packet.window_end_utc,
            cutoff_utc="2026-09-10T12:00:00Z",
            budget_units=packet.budget_units,
        ),
        per_board_cap=4,
        per_company_cap=2,
        budget_units=20,
        max_brave_requests=4,
        max_tavily_requests=4,
        max_board_candidates=10,
        max_board_verifications=8,
        max_wire_attempts=100,
        artifact_class="offline_private_report_only",
    )
    return authorization, accepted, plan, _config()


def _packet_doc(
    authorization: GateCAuthorization,
    accepted: AcceptedGateBBinding,
    plan: Any,
) -> dict[str, Any]:
    auth_mapping = dataclasses.asdict(authorization)
    auth_mapping["schema_version"] = GATE_C_AUTH_SCHEMA
    packet_hash = accepted.packet_sha256
    return {
        "gate_b_packet": accepted.packet.payload(),
        "gate_b_packet_sha256": packet_hash,
        "gate_b_report": {
            "result": "ready",
            "code": "gate_b_packet_ready",
            "packet_sha256": packet_hash,
        },
        "authorization": auth_mapping,
        "plan_sha256": plan.plan_sha256,
        "approval_reference_NOT_GRANTED": APPROVAL_REF,
    }


def _verifier(tmp_path: Path, **overrides: Any) -> IndependentPacketVerifier:
    arguments: dict[str, Any] = {
        "packet_path": tmp_path / "packet.json",
        "repo_path": tmp_path,
        "expected_approval_reference": APPROVAL_REF,
        "history_roots": (tmp_path,),
        "verdict_path": tmp_path / "verdict.json",
        "git_head": lambda: GIT_HEAD,
    }
    arguments.update(overrides)
    return IndependentPacketVerifier(**arguments)


def _write_packet(tmp_path: Path, doc: dict[str, Any]) -> Path:
    path = tmp_path / "packet.json"
    path.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    return path


def test_valid_packet_passes_and_writes_seed_free_verdict(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    verifier = _verifier(tmp_path)
    claims = verifier.verify_real_discovery(authorization, accepted, plan, config)
    assert type(claims) is RealDiscoveryVerification
    assert claims.operation_id == OPERATION_ID
    raw = (tmp_path / "verdict.json").read_text(encoding="utf-8")
    assert SELECTION not in raw and PARTITION not in raw
    verdict = json.loads(raw)
    assert verdict["gate_b_packet_sha256"] == accepted.packet_sha256
    assert verdict["query_plan_sha256"] == plan.plan_sha256
    assert len(verdict["checks"]) == 11


def test_capability_path_accepts_production_verifier(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _verifier(tmp_path), now=NOW
    )
    assert capability.claims.namespace == "r2-verifier-test"


def test_tampered_file_rejects_without_verdict(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    doc = _packet_doc(authorization, accepted, plan)
    doc["gate_b_packet"]["namespace"] = "tampered-namespace"
    _write_packet(tmp_path, doc)
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_binding_mismatch"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)
    assert not (tmp_path / "verdict.json").exists()


def test_forged_objects_against_honest_file_reject(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    forged_packet = dataclasses.replace(accepted.packet, selection_seed="c3" * 32)
    forged_hash = gate_b_packet_sha256(forged_packet)
    forged_accepted = AcceptedGateBBinding(
        forged_packet,
        forged_hash,
        PreflightReport(
            result="ready",
            code="gate_b_packet_ready",
            code_commit_sha256=forged_packet.code_commit_sha256,
            profile_sha256=forged_packet.profile_sha256,
            policy_sha256=forged_packet.policy_sha256,
            packet_sha256=forged_hash,
        ),
    )
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_binding_mismatch"):
        _verifier(tmp_path).verify_real_discovery(authorization, forged_accepted, plan, config)
    assert not (tmp_path / "verdict.json").exists()


def test_packet_section_without_schema_marker_passes(tmp_path: Path) -> None:
    """The approved real packet carries raw constructor fields, no marker."""
    authorization, accepted, plan, config = _bundle(tmp_path)
    doc = _packet_doc(authorization, accepted, plan)
    del doc["gate_b_packet"]["schema_version"]
    _write_packet(tmp_path, doc)
    claims = _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)
    assert type(claims) is RealDiscoveryVerification


def test_wrong_schema_marker_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    doc = _packet_doc(authorization, accepted, plan)
    doc["authorization"]["schema_version"] = "tampered-schema-v9"
    _write_packet(tmp_path, doc)
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_authorization_invalid"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)


def test_excessive_ttl_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    doc = _packet_doc(authorization, accepted, plan)
    doc["authorization"]["expires_at_utc"] = "2026-09-12T00:00:00Z"
    _write_packet(tmp_path, doc)
    rebuilt_auth = parse_rebuilt_authorization(doc)
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_window_invalid"):
        _verifier(tmp_path).verify_real_discovery(rebuilt_auth, accepted, plan, config)


def parse_rebuilt_authorization(doc: dict[str, Any]) -> GateCAuthorization:
    from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
        parse_gate_c_authorization,
    )

    return parse_gate_c_authorization(doc["authorization"])


def test_wrong_approval_reference_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    verifier = _verifier(tmp_path, expected_approval_reference="some-other-reference")
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_approval_unbound"):
        verifier.verify_real_discovery(authorization, accepted, plan, config)


def test_paid_quota_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, _ = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_quota_invalid"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, _config(paid=True))


def test_seed_reuse_in_history_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    (tmp_path / "notes.txt").write_text(f"old secret {SELECTION}\n", encoding="utf-8")
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_seed_reused"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)


def test_commit_mismatch_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    verifier = _verifier(tmp_path, git_head=lambda: "cd" * 20)
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_commit_mismatch"):
        verifier.verify_real_discovery(authorization, accepted, plan, config)


def test_unreadable_packet_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    (tmp_path / "packet.json").write_text("not json{", encoding="utf-8")
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_packet_unreadable"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)


def test_missing_section_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    doc = _packet_doc(authorization, accepted, plan)
    del doc["authorization"]
    _write_packet(tmp_path, doc)
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_packet_fields_invalid"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)


def test_malformed_seed_in_file_rejects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    doc = _packet_doc(authorization, accepted, plan)
    doc["gate_b_packet"]["selection_seed"] = "zz" * 32
    _write_packet(tmp_path, doc)
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_packet_fields_invalid"):
        _verifier(tmp_path).verify_real_discovery(authorization, accepted, plan, config)


def test_constructor_rejects_bad_types(tmp_path: Path) -> None:
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_type_invalid"):
        IndependentPacketVerifier(
            packet_path="packet.json",  # type: ignore[arg-type]
            repo_path=tmp_path,
            expected_approval_reference=APPROVAL_REF,
        )
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_type_invalid"):
        IndependentPacketVerifier(
            packet_path=tmp_path / "packet.json",
            repo_path=tmp_path,
            expected_approval_reference="",
        )


def test_verify_rejects_wrong_input_types(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    _write_packet(tmp_path, _packet_doc(authorization, accepted, plan))
    with pytest.raises(RealDiscoveryVerifierError, match="verdict_type_invalid"):
        _verifier(tmp_path).verify_real_discovery(
            "nope",  # type: ignore[arg-type]
            accepted,
            plan,
            config,
        )
