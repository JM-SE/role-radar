"""Focused offline Gate B packet preflight coverage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    build_packet_bytes,
    load_packet_bytes,
    run_gate_b_preflight,
)

SELECTION = "a" * 64
PARTITION = "b" * 64
HASH = "c" * 64


def _packet(root: Path) -> GateBPacket:
    return GateBPacket(
        code_commit_sha256=HASH,
        namespace="r2-gate-b-test",
        root=str(root),
        selection_seed=SELECTION,
        partition_seed=PARTITION,
        seed_origin="operator_supplied",
        seed_generated=False,
        profile_id="profile-v1",
        profile_version="1",
        profile_sha256=HASH,
        policy_id="policy-v1",
        policy_version="1",
        policy_sha256=HASH,
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


def test_valid_explicit_packet_returns_ready_without_writing(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    path = tmp_path / "packet.json"
    path.write_bytes(build_packet_bytes(packet))
    before = path.read_bytes()

    report = run_gate_b_preflight(path=path, artifact_root=tmp_path)

    assert report.as_dict() == {
        "code": "gate_b_packet_ready",
        "code_commit_sha256": HASH,
        "policy_sha256": HASH,
        "profile_sha256": HASH,
        "packet_sha256": hashlib.sha256(build_packet_bytes(packet)).hexdigest(),
        "result": "ready",
        "schema_version": "f10.1f-gate-b-packet-v1",
    }
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value", "code"),
    (
        ("selection_seed", "a" * 63, "selection_seed_invalid"),
        ("partition_seed", SELECTION, "seeds_must_differ"),
        ("seed_generated", True, "seed_origin_invalid"),
        ("historical_reference", True, "historical_reference_rejected"),
        (
            "authority_reference",
            "2026-08-25-f10-01f-live-prereg-proposal",
            "authority_reference_rejected",
        ),
        ("corpus_count", 0, "cardinality_invalid"),
        ("budget_units", 0, "budget_invalid"),
    ),
)
def test_invalid_explicit_values_block(
    field: str, value: object, code: str, tmp_path: Path
) -> None:
    packet = _packet(tmp_path)
    payload = packet.payload()
    payload[field] = value
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    report = run_gate_b_preflight(path=tmp_path / "packet.json", artifact_root=tmp_path)
    assert report.result == "blocked"
    assert report.code == "packet_file_invalid"

    # The service must also block a syntactically valid but semantically invalid packet.
    (tmp_path / "packet.json").write_bytes(raw)
    report = run_gate_b_preflight(path=tmp_path / "packet.json", artifact_root=tmp_path)
    assert report.result == "blocked"
    assert report.code == code


def test_unknown_or_noncanonical_fields_block(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    payload = packet.payload()
    payload["unexpected"] = "reject"
    with pytest.raises(ValueError) as exc:
        load_packet_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    assert getattr(exc.value, "code", "") == "packet_fields_invalid"


def test_packet_root_must_match_explicit_read_root(tmp_path: Path) -> None:
    packet = _packet(tmp_path / "nested")
    path = tmp_path / "packet.json"
    path.write_bytes(build_packet_bytes(packet))
    report = run_gate_b_preflight(path=path, artifact_root=tmp_path)
    assert report.result == "blocked"
    assert report.code == "packet_root_mismatch"


def test_gate_b_cli_preflight_is_read_only_and_c_f_remain_blocked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    packet = _packet(tmp_path)
    packet_path = tmp_path / "packet.json"
    packet_path.write_bytes(build_packet_bytes(packet))
    before = packet_path.read_bytes()

    args = type(
        "Args",
        (),
        {
            "f10_1f_command": "preflight",
            "file": str(packet_path),
            "artifact_root": str(tmp_path),
        },
    )()
    assert evaluation_f10_1f.run(args) == 0
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    assert output["result"] == "ready"
    assert packet_path.read_bytes() == before

    assert evaluation_f10_1f.run(type("Args", (), {"f10_1f_command": "freeze"})()) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "BLOCK-0"
