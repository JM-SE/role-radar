"""Offline Gate C authorization and pre-effect boundary checks."""

from __future__ import annotations

import hashlib
from argparse import Namespace
from pathlib import Path

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    PreflightReport,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorizationError,
    gate_b_packet_sha256,
    parse_gate_c_authorization,
)


def _packet(root: Path) -> GateBPacket:
    value = "c" * 64
    return GateBPacket(
        code_commit_sha256=value,
        namespace="r2-gate-c-test",
        root=str(root),
        selection_seed="a" * 64,
        partition_seed="b" * 64,
        seed_origin="operator_supplied",
        seed_generated=False,
        profile_id="profile-v1",
        profile_version="1",
        profile_sha256=value,
        policy_id="policy-v1",
        policy_version="1",
        policy_sha256=value,
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


def test_gate_c_authorization_parser_forbids_unknown_fields() -> None:
    with pytest.raises(GateCAuthorizationError) as error:
        parse_gate_c_authorization({"schema_version": "wrong", "unexpected": True})
    assert error.value.code == "authorization_fields_invalid"


def test_gate_c_cli_missing_authorization_is_block_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert evaluation_f10_1f.run(Namespace(f10_1f_command="run-report-only")) == 2
    assert '"code":"gate_c_authorization_required"' in capsys.readouterr().out


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
