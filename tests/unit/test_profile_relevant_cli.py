"""Focused offline CLI contracts for F10.1F."""

from __future__ import annotations

import json
from argparse import Namespace
from typing import cast

import pytest

from role_radar.cli import evaluation_f10_1f
from role_radar.cli.main import _parser


def _json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    return cast(dict[str, object], json.loads(capsys.readouterr().out))


def test_parser_registers_f10_1f_commands_without_required_acknowledgement() -> None:
    parser = _parser()

    for command in (
        "provenance",
        "status",
        "verify",
        "run-report-only",
        "preregister",
        "acquire",
        "preview",
        "freeze",
    ):
        args = parser.parse_args(("evaluation", "f10-1f", command))
        assert args.evaluation_command == "f10-1f"
        assert args.f10_1f_command == command


def test_offline_commands_have_sanitized_stable_outputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert evaluation_f10_1f.run(Namespace(f10_1f_command="provenance")) == 0
    provenance = _json(capsys)
    assert provenance == {
        "code": "provenance_not_loaded",
        "command": "provenance",
        "live_execution": "disabled",
        "result": "offline",
        "schema_version": "f10.1f-cli-v1",
    }

    assert evaluation_f10_1f.run(Namespace(f10_1f_command="status")) == 0
    status = _json(capsys)
    assert status == {
        "code": "live_execution_disabled",
        "command": "status",
        "gates": {"C": "disabled", "D": "disabled", "E": "disabled", "F": "disabled"},
        "result": "offline_status",
        "schema_version": "f10.1f-cli-v1",
    }

    assert (
        evaluation_f10_1f.run(Namespace(f10_1f_command="verify", dataset_id="not-a-dataset")) == 2
    )
    verify = _json(capsys)
    assert verify == {
        "code": "dataset_id_invalid",
        "command": "verify",
        "result": "blocked",
        "schema_version": "f10.1f-cli-v1",
    }


def test_main_dispatches_f10_1f_before_settings(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from role_radar.cli import main as cli_main

    class SettingsMustNotBeConstructed:
        def __init__(self) -> None:
            raise AssertionError("F10.1F must not construct Settings")

    monkeypatch.setattr(cli_main, "Settings", SettingsMustNotBeConstructed)
    assert cli_main.main(["evaluation", "f10-1f", "freeze"]) == 2
    assert _json(capsys) == {
        "code": "BLOCK-0",
        "command": "freeze",
        "live_execution": "disabled",
        "result": "blocked",
        "schema_version": "f10.1f-cli-v1",
    }
