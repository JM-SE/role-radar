from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
)
from role_radar.evaluation.r2_real_gate_c_runner import (
    prepare_live_packet,
    run_live_gate_c,
)

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)
HASH = "a" * 64


def _template(tmp_path: Path) -> Path:
    root = tmp_path / "old-root"
    root.mkdir()
    packet = GateBPacket(
        code_commit_sha256=HASH,
        namespace="r2-template",
        root=str(root),
        selection_seed="b" * 64,
        partition_seed="c" * 64,
        seed_origin="operator_supplied",
        seed_generated=False,
        profile_id="00000000-0000-0000-0000-000000000001",
        profile_version="1",
        profile_sha256="d" * 64,
        policy_id="policy-v1",
        policy_version="1",
        policy_sha256="e" * 64,
        window_start_utc="2026-09-09T00:00:00Z",
        window_end_utc="2026-09-10T00:00:00Z",
        per_board_cap=4,
        per_company_cap=2,
        corpus_count=10,
        pilot_count=2,
        holdout_count=8,
        budget_units=20,
        historical_reference=False,
        authority_reference="new_planned_packet",
    )
    provenance = {
        "gate_b_packet_sha256": HASH,
        "candidate_commit_sha256": HASH,
        "profile_id": packet.profile_id,
        "profile_version": packet.profile_version,
        "profile_sha256": packet.profile_sha256,
        "policy_id": packet.policy_id,
        "policy_version": packet.policy_version,
        "policy_sha256": packet.policy_sha256,
        "query_plan_sha256": HASH,
        "namespace": packet.namespace,
        "approved_root": packet.root,
        "window_start_utc": packet.window_start_utc,
        "window_end_utc": packet.window_end_utc,
        "cutoff_utc": "2026-09-09T12:00:00Z",
        "budget_units": packet.budget_units,
    }
    expires_at = (datetime.now(UTC) + timedelta(hours=2)).replace(microsecond=0)
    document = {
        "approval_reference_NOT_GRANTED": "template-approval",
        "authorization": {
            "artifact_class": "offline_private_report_only",
            "budget_units": 20,
            "expires_at_utc": expires_at.isoformat().replace("+00:00", "Z"),
            "gate": "C",
            "lineage_id": "11111111-1111-4111-8111-111111111111",
            "max_board_candidates": 10,
            "max_board_verifications": 8,
            "max_brave_requests": 4,
            "max_tavily_requests": 4,
            "max_wire_attempts": 100,
            "mode": "report-only",
            "operation_id": "22222222-2222-4222-8222-222222222222",
            "per_board_cap": 4,
            "per_company_cap": 2,
            "provenance": provenance,
            "report_only": True,
            "schema_version": "f10.1f-gate-c-authorization-v1",
        },
        "capability_claims": {},
        "caps_budget": {
            "budget_units": 20,
            "corpus_count": 10,
            "holdout_count": 8,
            "max_board_candidates": 10,
            "max_board_verifications": 8,
            "max_brave_requests": 4,
            "max_tavily_requests": 4,
            "max_wire_attempts": 100,
            "per_board_cap": 4,
            "per_company_cap": 2,
            "pilot_count": 2,
        },
        "gate_b_packet": packet.payload(),
        "plan_sha256": HASH,
        "quota": {
            "config_version": "config-v1",
            "paid_disabled": True,
            "utc_month": "2026-09",
        },
        "revision": 1,
    }
    path = tmp_path / "template.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_prepare_live_packet_regenerates_binding_and_short_window(tmp_path: Path) -> None:
    template = _template(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    packet = evidence / "fresh.json"

    result = prepare_live_packet(
        template_path=template,
        output_path=packet,
        evidence_root=evidence,
        approval_reference="operator-approval-now",
        repo_path=Path.cwd(),
        now=NOW,
        ttl_seconds=90 * 60,
    )

    output = json.loads(packet.read_text(encoding="utf-8"))
    assert result["result"] == "prepared"
    assert output["approval_reference_NOT_GRANTED"] == "operator-approval-now"
    assert output["authorization"]["provenance"]["approved_root"] == str(evidence)
    assert output["authorization"]["expires_at_utc"] == "2026-09-09T13:30:00Z"
    assert output["gate_b_packet"]["selection_seed"] != "b" * 64
    assert output["gate_b_packet"]["partition_seed"] != "c" * 64
    assert packet.stat().st_mode & 0o777 == 0o600


def test_run_live_gate_c_rejects_wrong_operator_approval_before_runtime(tmp_path: Path) -> None:
    packet = _template(tmp_path)

    with pytest.raises(ValueError, match="r2_gate_c_approval_invalid"):
        run_live_gate_c(
            packet_path=packet,
            repo_path=Path.cwd(),
            history_roots=(Path.cwd(),),
            verdict_path=tmp_path / "verdict.json",
            approval_reference="wrong-approval",
            config=object(),
            plan=object(),
            session=object(),
        )
