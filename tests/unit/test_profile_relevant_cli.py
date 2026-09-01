"""Focused offline CLI contracts for F10.1F."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
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

    with pytest.raises(SystemExit):
        parser.parse_args(("evaluation", "f10-1f", "synthetic"))


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


def test_provenance_file_read_rejects_absolute_symlink_and_oversized_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path
    allowed = root / "artifact.json"
    allowed.write_bytes(b"{}\n")
    (root / "link.json").symlink_to(allowed)
    (root / "large.json").write_bytes(b"x" * (128 * 1024 + 1))
    monkeypatch.chdir(root)

    for filename in (str(allowed), "link.json", "large.json"):
        assert (
            evaluation_f10_1f.run(
                Namespace(
                    f10_1f_command="provenance",
                    file=filename,
                    artifact_root=str(root),
                )
            )
            == 2
        )
        assert _json(capsys)["code"] == "provenance_invalid"

    outside = root.parent / "outside.json"
    outside.write_bytes(b"{}\n")
    assert (
        evaluation_f10_1f.run(
            Namespace(
                f10_1f_command="provenance",
                file=str(outside),
                artifact_root=str(root),
            )
        )
        == 2
    )
    assert _json(capsys)["code"] == "provenance_invalid"


@pytest.mark.parametrize(
    ("command", "arguments"),
    (
        ("discover", ("--confirmation", "I ACKNOWLEDGE F10.1 LIVE DISCOVERY REPORT ONLY")),
        ("acquire", ("--file", "plan.json", "--plan-sha256", "a" * 64, "--acknowledgement", "ack")),
        ("verify", ("--dataset-id", "a" * 64)),
    ),
)
def test_historical_f10_1_live_commands_are_blocked_before_settings_or_dependencies(
    command: str,
    arguments: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from role_radar.cli import main as cli_main

    class SettingsMustNotBeConstructed:
        def __init__(self) -> None:
            raise AssertionError("historical F10.1 command reached settings")

    monkeypatch.setattr(cli_main, "Settings", SettingsMustNotBeConstructed)
    assert cli_main.main(("evaluation", "f10-1", command, *arguments)) == 2
    assert _json(capsys) == {
        "code": "historical_command_non_executable",
        "historical": True,
        "result": "blocked",
        "schema_version": "f10.1-historical-cli-v1",
    }


@pytest.mark.parametrize("command", ("preflight", "plan", "status", "abort"))
def test_historical_f10_1c_aliases_are_blocked_uniformly(
    command: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from role_radar.cli import main as cli_main

    monkeypatch.setattr(cli_main, "Settings", lambda: (_ for _ in ()).throw(AssertionError()))
    args = ("evaluation", "f10-1c", command)
    assert cli_main.main(args) == 2
    assert _json(capsys) == {
        "code": "historical_command_non_executable",
        "historical": True,
        "result": "blocked",
        "schema_version": "f10.1-historical-cli-v1",
    }
