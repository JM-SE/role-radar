"""Pure capability boundary for real Gate C discovery; no IO, no credentials."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCProvenance,
    gate_b_packet_sha256,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_capability import (
    ApprovedRealDiscoveryCapability,
    RealDiscoveryCapabilityError,
    RealDiscoveryVerification,
    capability_from_independent_verifier,
    make_test_real_discovery_verification,
)

NOW = datetime.now(UTC).replace(microsecond=0)
OPERATION_ID = "11111111-1111-4111-8111-111111111111"


def _packet(root: Path) -> GateBPacket:
    value = "c" * 64
    return GateBPacket(
        code_commit_sha256=value,
        namespace="r2-real-discovery-test",
        root=str(root),
        selection_seed="a" * 64,
        partition_seed="b" * 64,
        seed_origin="operator_supplied",
        seed_generated=False,
        profile_id="00000000-0000-0000-0000-000000000001",
        profile_version="1",
        profile_sha256=value,
        policy_id="policy-v1",
        policy_version="1",
        policy_sha256=value,
        window_start_utc=NOW.isoformat().replace("+00:00", "Z"),
        window_end_utc=(NOW + timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        per_board_cap=10,
        per_company_cap=10,
        corpus_count=10,
        pilot_count=2,
        holdout_count=8,
        budget_units=100,
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


def _config() -> Any:
    quota = lambda handle: SimpleNamespace(  # noqa: E731
        enabled=True, units_limit=4, credential_handle=handle
    )
    return SimpleNamespace(
        config_version="config-v1",
        brave_free=quota("brave-free"),
        tavily_free=quota("tavily-free"),
    )


class _FakeVerifier:
    def __init__(self, mutate=None) -> None:
        self.mutate = mutate
        self.calls = 0

    def verify_real_discovery(
        self, authorization: Any, accepted_b: Any, plan: Any, config: Any
    ) -> RealDiscoveryVerification:
        self.calls += 1
        verification = make_test_real_discovery_verification(
            authorization, accepted_b, plan, config
        )
        if self.mutate is not None:
            return self.mutate(verification)
        return verification


def _bundle(tmp_path: Path) -> tuple[Any, Any, Any, Any]:
    from dataclasses import replace

    plan = _plan()
    # Bind the packet policy hash to the generated plan so Gate C
    # predecessor checks pass; the plan itself is code-generated.
    packet = replace(_packet(tmp_path), policy_sha256=plan.policy_sha256)
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
    provenance = GateCProvenance(
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
        cutoff_utc=(NOW + timedelta(hours=12)).isoformat().replace("+00:00", "Z"),
        budget_units=packet.budget_units,
    )
    expires_at = (datetime.now(UTC) + timedelta(hours=2)).replace(microsecond=0)
    authorization = GateCAuthorization(
        gate="C",
        mode="report-only",
        report_only=True,
        operation_id=OPERATION_ID,
        lineage_id="22222222-2222-4222-8222-222222222222",
        expires_at_utc=expires_at.isoformat().replace("+00:00", "Z"),
        provenance=provenance,
        per_board_cap=10,
        per_company_cap=10,
        budget_units=100,
        max_brave_requests=4,
        max_tavily_requests=4,
        max_board_candidates=10,
        max_board_verifications=8,
        max_wire_attempts=100,
        artifact_class="offline_private_report_only",
    )
    return authorization, accepted, plan, _config()


def test_valid_capability_verifies(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    verifier = _FakeVerifier()
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, verifier, now=NOW
    )
    assert type(capability) is ApprovedRealDiscoveryCapability
    capability.verify_for(authorization, accepted, plan, config, now=NOW)
    assert verifier.calls == 1


def test_verifier_required(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization,
            accepted,
            plan,
            config,
            None,
            now=NOW,  # type: ignore[arg-type]
        )


def test_direct_construction_blocked() -> None:
    with pytest.raises(TypeError):
        ApprovedRealDiscoveryCapability()  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        RealDiscoveryVerification()  # type: ignore[call-arg]


def test_bool_verifier_output_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)

    class _BoolVerifier:
        def verify_real_discovery(self, *args: Any) -> Any:
            return True

    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization, accepted, plan, config, _BoolVerifier(), now=NOW
        )


def _forged(mutate) -> Any:
    return _FakeVerifier(mutate=mutate)


def test_forged_profile_hash_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)

    def mutate(verification: RealDiscoveryVerification) -> RealDiscoveryVerification:
        values = dict(verification.__dict__)
        values["profile_sha256"] = "d" * 64
        return RealDiscoveryVerification(**values, _token=_token())

    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization, accepted, plan, config, _forged(mutate), now=NOW
        )


def _token() -> object:
    import role_radar.evaluation.profile_relevant_acquisition.real_discovery_capability as module

    return module._TOKEN


def test_forged_destinations_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)

    def mutate(verification: RealDiscoveryVerification) -> RealDiscoveryVerification:
        values = dict(verification.__dict__)
        values["destinations"] = ("brave_search_api",)
        return RealDiscoveryVerification(**values, _token=_token())

    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization, accepted, plan, config, _forged(mutate), now=NOW
        )


def test_forged_bounds_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)

    def mutate(verification: RealDiscoveryVerification) -> RealDiscoveryVerification:
        values = dict(verification.__dict__)
        bounds = dict(values["bounds"])
        bounds["MAX_BRAVE_REQUESTS_PER_RUN"] = 24
        values["bounds"] = tuple(bounds.items())
        return RealDiscoveryVerification(**values, _token=_token())

    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization, accepted, plan, config, _forged(mutate), now=NOW
        )


def test_expired_capability_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    verifier = _FakeVerifier()
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, verifier, now=NOW
    )
    with pytest.raises(RealDiscoveryCapabilityError):
        capability.verify_for(
            authorization,
            accepted,
            plan,
            config,
            now=NOW + timedelta(hours=6),
        )


def test_pre_window_use_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    verifier = _FakeVerifier()
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, verifier, now=NOW
    )
    with pytest.raises(RealDiscoveryCapabilityError):
        capability.verify_for(
            authorization,
            accepted,
            plan,
            config,
            now=NOW - timedelta(hours=1),
        )


def test_paid_search_config_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    config.brave_paid = SimpleNamespace(enabled=True)
    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization, accepted, plan, config, _FakeVerifier(), now=NOW
        )


def test_ttl_max_is_separate_from_discovery_budgets(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    assert authorization.budget_units == 100
    verifier = _FakeVerifier()
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, verifier, now=NOW
    )
    assert capability.claims.ttl_seconds == 86400
    assert capability.claims.budget_units == 100


def test_excessive_ttl_rejected(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)

    def mutate(verification: RealDiscoveryVerification) -> RealDiscoveryVerification:
        values = dict(verification.__dict__)
        values["ttl_seconds"] = 86401
        return RealDiscoveryVerification(**values, _token=_token())

    with pytest.raises(RealDiscoveryCapabilityError):
        capability_from_independent_verifier(
            authorization, accepted, plan, config, _forged(mutate), now=NOW
        )
