from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from role_radar.continuous_acquisition.discovery_artifacts_v2 import (
    ReportOnlyVerifiedSourceV1,
    parse_terminal_report,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_recovery import (
    GateCRecoveryError,
    RecoveryTrustAnchor,
    _operation,
    _packet,
    _read_json,
    _source_configs,
    _validate_recovery_window,
    _validate_terminal_requests,
    recover_completed_partial,
)
from role_radar.evaluation.profile_relevant_acquisition.real_gate_c_discovery import (
    has_usable_real_discovery_result,
)

HISTORICAL_ROOT = Path(
    os.environ.get(
        "ROLE_RADAR_GATE_C_RECOVERY_FIXTURE",
        "/home/jmse/r2-evidence/r2-discover-20260911-clean-024003",
    )
)
OPERATION_ID = "ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5"
OPERATION_DIR = HISTORICAL_ROOT / "report-only" / "operations" / OPERATION_ID


def _historical_anchor() -> RecoveryTrustAnchor:
    packet = json.loads((HISTORICAL_ROOT / "gate-c-packet.json").read_text(encoding="utf-8"))
    terminal = parse_terminal_report((OPERATION_DIR / "terminal-report-v1.json").read_bytes())
    gate_b = packet["gate_b_packet"]
    return RecoveryTrustAnchor(
        operation_id=terminal.operation_id,
        profile_id=gate_b["profile_id"],
        profile_version=int(gate_b["profile_version"]),
        profile_sha256=gate_b["profile_sha256"],
        policy_sha256=gate_b["policy_sha256"],
        plan_sha256=terminal.plan_sha256,
        report_sha256=terminal.report_sha256,
        state=terminal.state,
        terminal_code=terminal.terminal_code or "",
        source_keys=tuple(source.source_key for source in terminal.verified_sources),
        search_request_identities=tuple(
            request.request_identity_sha256
            for request in terminal.requests
            if request.kind == "search"
        ),
        official_request_identities=tuple(
            request.request_identity_sha256
            for request in terminal.requests
            if request.kind == "official_verification"
        ),
    )
TRUST_ANCHOR = RecoveryTrustAnchor(
    operation_id=OPERATION_ID,
    profile_id="818eded4-2f69-4e66-ad12-cd0749e4ab3e",
    profile_version=2,
    profile_sha256="2a01d22969d3a8811a3816adba699ffad3e2946ae2e54527e0495c63cc467918",
    policy_sha256="387ed6fa43c2be8001cf10a1b1fb645eead6f6cecefb606e450d53bd016f1cc0",
    plan_sha256="e7ea8287e7cb1d1d4f2f32ffb8c0db84b1889bf70be404a96778b34a9afc2b95",
    report_sha256="3f816b91d078e9f91ed78422f44189d61f265dee582a1daa4387337638817de0",
    state="completed_partial",
    terminal_code="multiple_budgets_exhausted",
    source_keys=(
        "greenhouse:twilio",
        "greenhouse:grafanalabs",
        "greenhouse:similarweb",
        "greenhouse:stackline",
        "greenhouse:postman",
        "greenhouse:figma",
    ),
    search_request_identities=(
        "fc4279038bd0630bdd8bd36e4c4541264ac460f70d8a86b217a348a35766fa37",
        "3e2181315a125d6852c7e1e3ca502c218990cdbfac210b4097782bb39daea998",
        "585e5aae3a20cd034aa78a064940365a59427d7f9e97b7be04f5a8e1816c7d28",
        "e0ce0d1a7b0a2918abf590139b370e1f8dbe8196b72eaebb23c08d6585614131",
    ),
    official_request_identities=(
        "2d6b7e9670378e31e0cc6c3787075b22d46ef7fdb6da17b5f5cb5277ed7aea09",
        "7af2a6c4b3ae6f85273ea346f176f8d6892278db2242b12ebcc521385ee66985",
        "a0fb48201f3dda291bc9437d24b4e8629ee12d66fc7f2c9061ff75c7cb72be8e",
        "964da20b8183f454d8dc0ae06d469176ce6975982618ca82ad36329b564ce066",
        "2a824ff99c9d044d4786aea414a933bec5abaab98b0be51bdedc3e13e24edd39",
        "c3bddb5fdaf4ae5e5caebdbfa0138e212d3115b435a6a8a63b4fe59d7a767af0",
        "502db48087234f5e008d1e9a7888d098ef8489085f40d012518c95db573cdfe5",
        "b321c2f6b69334039a725670bca9d60f785088e37834fa5ee8460bedfb0a2dd0",
    ),
)


def test_partial_result_requires_bounded_terminal_code() -> None:
    source = ReportOnlyVerifiedSourceV1(
        source_type="greenhouse",
        source_key="greenhouse:test",
        configuration={"board_token": "test"},
        configuration_sha256="a" * 64,
        postings_count=0,
        board_candidate_ordinal=1,
        request_identity_sha256="b" * 64,
    )
    counts = {
        "search_requests_attempted": 1,
        "search_requests_completed": 1,
        "classified_hits": 0,
        "unique_board_candidates_seen": 1,
        "unique_board_candidates_retained": 1,
        "board_verifications_attempted": 1,
        "boards_verified": 1,
        "verification_wire_attempts_consumed": 1,
    }
    no_truncation = {
        "unique_board_candidates": False,
        "board_verifications": False,
        "verification_wire_attempts": False,
    }
    assert has_usable_real_discovery_result(
        "completed", (source,), None, counts=counts, truncation=no_truncation
    )
    assert has_usable_real_discovery_result(
        "completed_partial",
        (source,),
        "multiple_budgets_exhausted",
        counts={
            **counts,
            "unique_board_candidates_seen": 10,
            "unique_board_candidates_retained": 10,
            "board_verifications_attempted": 8,
            "verification_wire_attempts_consumed": 100,
        },
        truncation={
            "unique_board_candidates": True,
            "board_verifications": True,
            "verification_wire_attempts": True,
        },
    )
    assert not has_usable_real_discovery_result(
        "completed_partial", (source,), None, counts=counts, truncation=no_truncation
    )
    assert not has_usable_real_discovery_result(
        "completed_partial",
        (source,),
        "provider_search_failed",
        counts=counts,
        truncation=no_truncation,
    )


@pytest.mark.skipif(not HISTORICAL_ROOT.is_dir(), reason="historical Gate C fixture unavailable")
def test_recovery_reuses_partial_artifact_without_repeating_operation(tmp_path: Path) -> None:
    historical_files = (
        HISTORICAL_ROOT / "gate-c-packet.json",
        OPERATION_DIR / "operation-v1.json",
        OPERATION_DIR / "terminal-report-v1.json",
    )
    before = {path: hashlib.sha256(path.read_bytes()).digest() for path in historical_files}
    recovery_root = tmp_path / "recovery"

    result = recover_completed_partial(
        historical_root=HISTORICAL_ROOT,
        packet_path=historical_files[0],
        operation_path=historical_files[1],
        terminal_report_path=historical_files[2],
        recovery_root=recovery_root,
        verdict_path=recovery_root / "recovery-verdict.json",
        approval_reference="r2-gate-c-20260911",
        trusted_anchor=TRUST_ANCHOR,
    )

    assert result.state == "completed_partial"
    assert result.verified_source_count == 6
    assert result.evidence_path.stat().st_mode & 0o777 == 0o600
    assert result.manifest_path.stat().st_mode & 0o777 == 0o600
    assert result.verdict_path.stat().st_mode & 0o777 == 0o600
    assert recovery_root.stat().st_mode & 0o777 == 0o700
    assert b"https://" not in result.evidence_path.read_bytes()
    assert b"credentials" not in result.evidence_path.read_bytes()

    repeated = recover_completed_partial(
        historical_root=HISTORICAL_ROOT,
        packet_path=historical_files[0],
        operation_path=historical_files[1],
        terminal_report_path=historical_files[2],
        recovery_root=recovery_root,
        verdict_path=recovery_root / "recovery-verdict.json",
        approval_reference="r2-gate-c-20260911",
        trusted_anchor=TRUST_ANCHOR,
    )
    assert repeated.source_plan_sha256 == result.source_plan_sha256
    assert {path: hashlib.sha256(path.read_bytes()).digest() for path in historical_files} == before

    manifest = result.manifest_path
    manifest.write_bytes(manifest.read_bytes() + b"conflict")
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_output_conflict"):
        recover_completed_partial(
            historical_root=HISTORICAL_ROOT,
            packet_path=historical_files[0],
            operation_path=historical_files[1],
            terminal_report_path=historical_files[2],
            recovery_root=recovery_root,
            verdict_path=recovery_root / "recovery-verdict.json",
            approval_reference="r2-gate-c-20260911",
            trusted_anchor=TRUST_ANCHOR,
        )


@pytest.mark.skipif(not HISTORICAL_ROOT.is_dir(), reason="historical Gate C fixture unavailable")
def test_recovery_rejects_packet_shape_and_root_overlap() -> None:
    packet_path = HISTORICAL_ROOT / "gate-c-packet.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["gate_b_report"] = {"result": "ready"}
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_packet_invalid"):
        _packet(packet, HISTORICAL_ROOT)

    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_root_overlap"):
        recover_completed_partial(
            historical_root=HISTORICAL_ROOT,
            packet_path=packet_path,
            operation_path=OPERATION_DIR / "operation-v1.json",
            terminal_report_path=OPERATION_DIR / "terminal-report-v1.json",
            recovery_root=HISTORICAL_ROOT,
            verdict_path=HISTORICAL_ROOT / "recovery-verdict.json",
            approval_reference="r2-gate-c-20260911",
        )


@pytest.mark.skipif(not HISTORICAL_ROOT.is_dir(), reason="historical Gate C fixture unavailable")
def test_recovery_rejects_operation_provider_binding() -> None:
    packet = json.loads((HISTORICAL_ROOT / "gate-c-packet.json").read_text(encoding="utf-8"))
    accepted_b, auth = _packet(packet, HISTORICAL_ROOT)
    operation_path = OPERATION_DIR / "operation-v1.json"
    operation = json.loads(operation_path.read_text(encoding="utf-8"))
    operation["providers"][0]["provider"] = "tavily"
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_operation_binding_invalid"):
        _operation(operation, accepted_b.packet, auth)


@pytest.mark.skipif(not HISTORICAL_ROOT.is_dir(), reason="historical Gate C fixture unavailable")
def test_recovery_rejects_terminal_after_outer_packet_expiry() -> None:
    packet = json.loads((HISTORICAL_ROOT / "gate-c-packet.json").read_text(encoding="utf-8"))
    accepted_b, auth = _packet(packet, HISTORICAL_ROOT)
    operation_payload = json.loads(
        (OPERATION_DIR / "operation-v1.json").read_text(encoding="utf-8")
    )
    operation = _operation(operation_payload, accepted_b.packet, auth)
    terminal = parse_terminal_report(
        (OPERATION_DIR / "terminal-report-v1.json").read_bytes()
    )
    outer_expiry = datetime.fromisoformat(auth["expires_at_utc"].replace("Z", "+00:00"))
    late = replace(
        terminal,
        completed_at_utc=outer_expiry + timedelta(seconds=1),
        report_sha256="0" * 64,
    )
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_window_invalid"):
        _validate_recovery_window(accepted_b.packet, auth, operation, late)


@pytest.mark.skipif(not HISTORICAL_ROOT.is_dir(), reason="historical Gate C fixture unavailable")
def test_recovery_rejects_source_request_identity_mismatch() -> None:
    terminal = parse_terminal_report((OPERATION_DIR / "terminal-report-v1.json").read_bytes())
    operation = json.loads((OPERATION_DIR / "operation-v1.json").read_text(encoding="utf-8"))
    changed = replace(terminal.verified_sources[0], request_identity_sha256="0" * 64)
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_sources_invalid"):
        _source_configs(
            (changed, *terminal.verified_sources[1:]),
            operation["operation_sha256"],
            terminal.requests,
        )


@pytest.mark.skipif(not HISTORICAL_ROOT.is_dir(), reason="historical Gate C fixture unavailable")
def test_recovery_rejects_request_ordinal_and_count_mismatch() -> None:
    packet = json.loads((HISTORICAL_ROOT / "gate-c-packet.json").read_text(encoding="utf-8"))
    accepted_b, auth = _packet(packet, HISTORICAL_ROOT)
    operation = _operation(
        json.loads((OPERATION_DIR / "operation-v1.json").read_text(encoding="utf-8")),
        accepted_b.packet,
        auth,
    )
    terminal = parse_terminal_report((OPERATION_DIR / "terminal-report-v1.json").read_bytes())
    duplicate_ordinal = replace(terminal.requests[1], request_ordinal=1)
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_request_invalid"):
        _validate_terminal_requests(
            replace(
                terminal,
                requests=(terminal.requests[0], duplicate_ordinal, *terminal.requests[2:]),
                report_sha256="0" * 64,
            ),
            auth,
        )
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_terminal_counts_invalid"):
        _validate_terminal_requests(
            replace(
                terminal,
                counts={**terminal.counts, "boards_verified": 5},
                report_sha256="0" * 64,
            ),
            auth,
        )
    assert operation.operation_id == terminal.operation_id


@pytest.mark.parametrize(
    "payload",
    [
        b'{"value":1,"value":2}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":' + (b'[' * 18) + b'0' + (b']' * 18) + b'}',
    ],
)
def test_recovery_uses_bounded_strict_json_loader(tmp_path: Path, payload: bytes) -> None:
    root = tmp_path / "historical"
    root.mkdir(mode=0o700)
    path = root / "artifact.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_artifact_invalid"):
        _read_json(path, root=root)


def test_recovery_rejects_unbounded_or_path_like_approval_before_output(tmp_path: Path) -> None:
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_approval_required"):
        recover_completed_partial(
            historical_root=HISTORICAL_ROOT,
            packet_path=HISTORICAL_ROOT / "gate-c-packet.json",
            operation_path=OPERATION_DIR / "operation-v1.json",
            terminal_report_path=OPERATION_DIR / "terminal-report-v1.json",
            recovery_root=tmp_path / "recovery",
            verdict_path=tmp_path / "recovery" / "recovery-verdict.json",
            approval_reference="../unsafe",
        )
    with pytest.raises(GateCRecoveryError, match="gate_c_recovery_approval_required"):
        recover_completed_partial(
            historical_root=HISTORICAL_ROOT,
            packet_path=HISTORICAL_ROOT / "gate-c-packet.json",
            operation_path=OPERATION_DIR / "operation-v1.json",
            terminal_report_path=OPERATION_DIR / "terminal-report-v1.json",
            recovery_root=tmp_path / "recovery-2",
            verdict_path=tmp_path / "recovery-2" / "recovery-verdict.json",
            approval_reference="a" * 129,
        )


def test_recovery_cli_import_does_not_load_live_dependencies() -> None:
    code = """
import sys
import role_radar.cli.evaluation_r2_real_gate_c
blocked = {
    'httpx', 'sqlalchemy', 'role_radar.credentials',
    'role_radar.repositories.acquisition',
    'role_radar.evaluation.r2_real_gate_c_runner',
}
assert not blocked.intersection(sys.modules)
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
