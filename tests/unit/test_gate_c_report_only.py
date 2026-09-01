"""Offline Gate C authorization and pre-effect boundary checks."""

from __future__ import annotations

import hashlib
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.discovery.board_candidates import BoardCandidateV2
from role_radar.discovery.planner_v2 import plan_profile_discovery
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1, policy_sha256
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
    GateCAuthorizationError,
    GateCProvenance,
    gate_b_packet_sha256,
    parse_gate_c_authorization,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import (
    GateCServiceError,
    execute_gate_c_report_only,
)


def _packet(root: Path, policy_sha: str = "c" * 64) -> GateBPacket:
    value = "c" * 64
    return GateBPacket(
        code_commit_sha256=value,
        namespace="r2-gate-c-test",
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
        policy_sha256=policy_sha,
        window_start_utc="2026-09-01T00:00:00Z",
        window_end_utc="2026-09-02T00:00:00Z",
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


def _authorization(root: Path, plan: Any) -> GateCAuthorization:
    packet = _packet(root, plan.policy_sha256)
    packet_hash = gate_b_packet_sha256(packet)
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
        cutoff_utc="2026-09-01T12:00:00Z",
        budget_units=packet.budget_units,
    )
    return GateCAuthorization(
        gate="C",
        mode="report-only",
        report_only=True,
        operation_id="gate-c-op",
        lineage_id="gate-c-lineage",
        expires_at_utc="2099-01-01T00:00:00Z",
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


def _accepted(root: Path, plan: Any | None = None) -> AcceptedGateBBinding:
    packet = _packet(root, plan.policy_sha256 if plan is not None else "c" * 64)
    packet_hash = gate_b_packet_sha256(packet)
    return AcceptedGateBBinding(
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


class _OfficialProvider:
    offline = True

    def __init__(self, candidates: tuple[BoardCandidateV2, ...]) -> None:
        self.candidates = candidates
        self.calls = 0

    def official_board_configurations(self, plan: Any) -> tuple[BoardCandidateV2, ...]:
        self.calls += 1
        return self.candidates


def _candidate(
    source_type: str, source_key: str, configuration: dict[str, str]
) -> BoardCandidateV2:
    return BoardCandidateV2(
        source_type=cast(Any, source_type),
        source_key=source_key,
        configuration=configuration,
        canonical_url="https://boards.example.invalid",
        query_ordinal=1,
        provider="brave",
        rank=1,
    )


def test_gate_c_authorization_parser_forbids_unknown_fields() -> None:
    with pytest.raises(GateCAuthorizationError) as error:
        parse_gate_c_authorization({"schema_version": "wrong", "unexpected": True})
    assert error.value.code == "authorization_fields_invalid"


def test_gate_c_cli_missing_authorization_is_block_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert evaluation_f10_1f.run(Namespace(f10_1f_command="run-report-only")) == 2
    assert '"code":"gate_c_authorization_required"' in capsys.readouterr().out


def test_gate_c_cli_dispatches_only_explicitly_injected_verified_objects(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = _plan()
    provider = _OfficialProvider(
        (_candidate("greenhouse", "greenhouse:acme", {"board_token": "acme"}),)
    )
    args = Namespace(
        f10_1f_command="run-report-only",
        authorization="artifact",
        gate_b_packet="packet",
        plan="plan",
        evidence_root=str(tmp_path),
        authorization_object=_authorization(tmp_path, plan),
        accepted_b_object=_accepted(tmp_path, plan),
        plan_object=plan,
        provider=provider,
    )
    assert evaluation_f10_1f.run(args) == 0
    assert provider.calls == 1
    assert '"code":"gate_c_report_only_completed"' in capsys.readouterr().out


def test_gate_c_acceptance_requires_explicit_ready_preflight_report(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    packet_hash = gate_b_packet_sha256(packet)
    report = PreflightReport(
        result="ready",
        code="gate_b_packet_ready",
        code_commit_sha256=packet.code_commit_sha256,
        profile_sha256=packet.profile_sha256,
        policy_sha256=packet.policy_sha256,
        packet_sha256=packet_hash,
    )
    accepted = AcceptedGateBBinding(packet, packet_hash, report)
    assert accepted.report is report

    with pytest.raises(GateCAuthorizationError) as error:
        AcceptedGateBBinding(
            packet,
            packet_hash,
            PreflightReport(result="blocked", code="packet_invalid"),
        )
    assert error.value.code == "gate_b_report_not_ready"


def test_gate_c_acceptance_rejects_report_hash_substitution(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    packet_hash = gate_b_packet_sha256(packet)
    with pytest.raises(GateCAuthorizationError) as error:
        AcceptedGateBBinding(
            packet,
            packet_hash,
            PreflightReport(
                result="ready",
                code="gate_b_packet_ready",
                code_commit_sha256=packet.code_commit_sha256,
                profile_sha256=packet.profile_sha256,
                policy_sha256=packet.policy_sha256,
                packet_sha256=hashlib.sha256(b"substituted").hexdigest(),
            ),
        )
    assert error.value.code == "gate_b_report_hash_mismatch"


def test_gate_c_report_only_is_one_offline_call_and_private_root_scoped(tmp_path: Path) -> None:
    plan = _plan()
    auth = _authorization(tmp_path, plan)
    provider = _OfficialProvider(
        (
            _candidate("greenhouse", "greenhouse:acme", {"board_token": "acme"}),
            _candidate("lever", "lever:global:acme", {"site": "acme", "region": "global"}),
        )
    )
    sentinel = tmp_path / "successor-sentinel"
    sentinel.write_text("untouched", encoding="utf-8")
    state = {"Source": (), "Job": (), "registration": ()}

    result = execute_gate_c_report_only(
        authorization=auth,
        accepted_b=_accepted(tmp_path, plan),
        plan=plan,
        provider=provider,
        evidence_root=tmp_path,
        before_after=lambda: (state.copy(), state.copy()),
    )

    assert provider.calls == 1
    assert result.source_plan is not None and result.source_plan.root == str(tmp_path)
    assert result.source_plan.source_configs == (
        {
            "family": "greenhouse",
            "source_key": "greenhouse:acme",
            "configuration_version": 1,
            "configuration": {"board_token": "acme"},
        },
        {
            "family": "lever",
            "source_key": "lever:global:acme",
            "configuration_version": 1,
            "configuration": {"site": "acme", "region": "global"},
        },
    )
    assert result.report is not None and result.report.plan_sha256 == plan.plan_sha256
    assert result.public.as_dict() == {
        "operation_id": "gate-c-op",
        "plan_sha256": plan.plan_sha256,
        "source_plan_sha256": result.source_plan.source_plan_sha256,
        "report_sha256": result.report.report_sha256,
        "query_count": 4,
        "host_count": 4,
        "family_counts": {"family_greenhouse": 2, "family_lever": 2},
        "budget_status": "within_bound",
        "result": "completed",
        "reason": None,
    }
    evidence = tmp_path / "gate-c" / plan.plan_sha256 / "private_evidence.json"
    assert evidence.is_file() and evidence.is_relative_to(tmp_path)
    assert sentinel.read_text(encoding="utf-8") == "untouched"
    assert {item.name for item in tmp_path.iterdir()} == {"gate-c", "successor-sentinel"}


@pytest.mark.parametrize("case", ("auth", "binding", "root", "provider"))
def test_gate_c_invalid_inputs_stop_before_runtime_or_evidence(tmp_path: Path, case: str) -> None:
    plan = _plan()
    auth = _authorization(tmp_path, plan)
    accepted = _accepted(tmp_path, plan)
    provider = _OfficialProvider(())
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("untouched", encoding="utf-8")
    if case == "auth":
        auth = object()  # type: ignore[assignment]
    elif case == "binding":
        plan = replace(plan, plan_sha256="d" * 64)
    elif case == "root":
        evidence_root = tmp_path / "other-root"
    else:
        provider = object()  # type: ignore[assignment]
    with pytest.raises((GateCAuthorizationError, GateCServiceError)):
        execute_gate_c_report_only(
            authorization=auth,
            accepted_b=accepted,
            plan=plan,
            provider=provider,
            evidence_root=locals().get("evidence_root", tmp_path),
        )
    assert provider.calls == 0 if isinstance(provider, _OfficialProvider) else True
    assert sentinel.read_text(encoding="utf-8") == "untouched"
    assert not (tmp_path / "gate-c").exists()


@pytest.mark.parametrize(
    ("source_type", "source_key", "configuration", "code"),
    (
        (
            "greenhouse",
            "greenhouse:other",
            {"board_token": "acme"},
            "official_board_configuration_substituted",
        ),
        (
            "greenhouse",
            "greenhouse:acme",
            {"board_token": "other"},
            "official_board_configuration_substituted",
        ),
        (
            "unknown",
            "unknown:acme",
            {"board_token": "acme"},
            "official_board_configuration_non_official",
        ),
    ),
)
def test_gate_c_rejects_nonofficial_or_substituted_source_configs(
    tmp_path: Path, source_type: str, source_key: str, configuration: dict[str, str], code: str
) -> None:
    plan = _plan()
    provider = _OfficialProvider((_candidate(source_type, source_key, configuration),))
    with pytest.raises(GateCServiceError) as error:
        execute_gate_c_report_only(
            authorization=_authorization(tmp_path, plan),
            accepted_b=_accepted(tmp_path, plan),
            plan=plan,
            provider=provider,
            evidence_root=tmp_path,
        )
    assert error.value.code == code
    assert not (tmp_path / "gate-c").exists()


def test_gate_c_rejects_duplicate_source_keys(tmp_path: Path) -> None:
    plan = _plan()
    candidate = _candidate("greenhouse", "greenhouse:acme", {"board_token": "acme"})
    with pytest.raises(GateCServiceError) as error:
        execute_gate_c_report_only(
            authorization=_authorization(tmp_path, plan),
            accepted_b=_accepted(tmp_path, plan),
            plan=plan,
            provider=_OfficialProvider((candidate, candidate)),
            evidence_root=tmp_path,
        )
    assert error.value.code == "official_board_configuration_substituted"
    assert not (tmp_path / "gate-c").exists()


def test_gate_c_public_dto_has_no_private_inputs_or_execution_details() -> None:
    fields = set(
        __import__(
            "role_radar.evaluation.profile_relevant_acquisition.gate_c_service",
            fromlist=["GateCPublicResult"],
        ).GateCPublicResult.__dataclass_fields__
    )
    assert fields == {
        "operation_id",
        "plan_sha256",
        "source_plan_sha256",
        "report_sha256",
        "query_count",
        "host_count",
        "family_counts",
        "budget_status",
        "result",
        "reason",
    }
    assert not {"seed", "root", "path", "query", "provider", "raw", "exception"} & fields
