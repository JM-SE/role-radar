"""Exhaustive invalid-acknowledgement boundary checks for Gate C through F."""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from role_radar.cli import evaluation_f10_1f

GATED = tuple(sorted(evaluation_f10_1f.GATED_COMMANDS))
ACK_CASES = {
    "missing": None,
    "stale": "F10.1F stale preview_sha256=" + "a" * 64,
    "malformed_hash_shaped": "F10.1F challenge_sha256=" + "g" * 64,
    "wrong_gate": "F10.1E challenge_sha256=" + "b" * 64,
    "cross_operation": "F10.1F operation=other-lineage challenge_sha256=" + "c" * 64,
    "cross_lineage": "F10.1F lineage=other-window challenge_sha256=" + "e" * 64,
    "failed_prerequisite": "F10.1F prerequisite=failed challenge_sha256=" + "f" * 64,
}


@pytest.mark.parametrize("command", GATED)
@pytest.mark.parametrize("acknowledgement", ACK_CASES.values(), ids=ACK_CASES.keys())
def test_invalid_acknowledgements_are_block_0_before_any_downstream_call_or_mutation(
    command: str,
    acknowledgement: str | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    mutations: list[str] = []

    def must_not_run(*_args: object, **_kwargs: object) -> None:
        calls.append("downstream")
        raise AssertionError("invalid acknowledgement reached a downstream gate")

    monkeypatch.setattr(evaluation_f10_1f, "_run_provenance", must_not_run)
    monkeypatch.setattr(evaluation_f10_1f, "_run_status", must_not_run)
    monkeypatch.setattr(evaluation_f10_1f, "_run_verify", must_not_run)
    monkeypatch.setattr(evaluation_f10_1f, "_print_block", evaluation_f10_1f._print_block)

    args = Namespace(f10_1f_command=command, acknowledgement=acknowledgement)
    before = tuple(mutations)
    assert evaluation_f10_1f.run(args) == 2
    payload = json.loads(capsys.readouterr().out)

    expected = {
        "code": "gate_c_authorization_required" if command == "run-report-only" else "BLOCK-0",
        "command": command,
        "result": "blocked",
        "schema_version": "f10.1f-cli-v1",
    }
    if command != "run-report-only":
        expected["live_execution"] = "disabled"
    assert payload == expected
    assert calls == []
    assert mutations == list(before) == []


def test_wrong_gate_acknowledgement_is_not_an_execution_switch(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = Namespace(
        f10_1f_command="preview",
        acknowledgement="F10.1F freeze challenge_sha256=" + "d" * 64,
    )
    assert evaluation_f10_1f.run(args) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "BLOCK-0"
