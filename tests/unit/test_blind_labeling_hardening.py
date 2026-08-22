"""Regression tests for F10.2 Gate-A hardening boundaries."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from role_radar.cli import evaluation_f10_2
from role_radar.evaluation.blind_labeling.contracts import Decision, Label
from role_radar.evaluation.blind_labeling.filesystem import (
    FilesystemError,
    publish_no_replace,
)
from role_radar.evaluation.blind_labeling.pilot_source import PilotSourceError
from role_radar.evaluation.blind_labeling.policy import RUBRIC_VERSION
from role_radar.evaluation.blind_labeling.runtime import BlindLabelingRuntime, RuntimeErrorCode
from role_radar.evaluation.blind_labeling.session import SessionError, new_session, save_first_pass
from role_radar.evaluation.blind_labeling.store import LabelingStore

from .test_blind_labeling_workflow import _fixture


def test_verify_route_uses_pinned_dataset_when_parser_omits_dataset_id(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeRuntime:
        def verify(self, labelset_id: str) -> dict[str, str]:
            assert labelset_id == "labelset"
            return {"status": "verified"}

    monkeypatch.setattr(evaluation_f10_2, "_runtime", lambda dataset_id: FakeRuntime())
    args = SimpleNamespace(f10_2_command="verify", labelset_id="labelset")

    assert evaluation_f10_2.run(args) == 0
    assert capsys.readouterr().out == '{"status":"verified"}\n'


def test_cli_rejects_non_pinned_dataset_id(capsys: pytest.CaptureFixture[str]) -> None:
    args = SimpleNamespace(f10_2_command="status", dataset_id="e" * 64)

    assert evaluation_f10_2.run(args) == 3
    assert '"code":"dataset_id_mismatch"' in capsys.readouterr().out


def test_cli_interactive_commands_require_real_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeRuntime:
        pass

    class NonTty:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(evaluation_f10_2, "_runtime", lambda dataset_id: FakeRuntime())
    monkeypatch.setattr(evaluation_f10_2.sys, "stdin", NonTty())
    args = SimpleNamespace(f10_2_command="label")

    assert evaluation_f10_2.run(args) == 130


def test_pilot_source_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    source, dataset_id = _fixture(real_parent / "source")
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    source = type(source)(
        alias / "source",
        dataset_id=dataset_id,
        pilot_sha256=source.pilot_sha256,
        pilot_file_sha256=source.pilot_file_sha256,
    )

    with pytest.raises(PilotSourceError, match="pilot_path_symlink"):
        source.load()


def test_pilot_source_requires_private_root_and_dataset_modes(tmp_path: Path) -> None:
    source, _ = _fixture(tmp_path / "source")
    source.root.chmod(0o755)
    with pytest.raises(PilotSourceError, match="pilot_root_private"):
        source.load()

    source, _ = _fixture(tmp_path / "source-2")
    source.path.parent.chmod(0o755)
    with pytest.raises(PilotSourceError, match="pilot_directory_mode"):
        source.load()


def test_publish_no_replace_never_overwrites_existing_target(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.write_bytes(b"new")
    target.write_bytes(b"old")

    with pytest.raises(FilesystemError, match="publish_conflict"):
        publish_no_replace(staging, target)

    assert target.read_bytes() == b"old"
    assert staging.read_bytes() == b"new"


def test_publish_no_replace_publishes_new_target_atomically(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.write_bytes(b"new")

    publish_no_replace(staging, target)

    assert target.read_bytes() == b"new"
    assert not staging.exists()


def test_first_pass_rejects_unknown_item_and_more_than_pilot_cardinality(tmp_path: Path) -> None:
    source, _ = _fixture(tmp_path / "source")
    snapshot = source.load()
    state = new_session(snapshot, "rubric", "r" * 64, "protocol", "now")
    decision = Decision(Label.APPLY, "role_match")
    allowed = frozenset(item.opaque_id for item in snapshot.items)

    with pytest.raises(SessionError, match="pilot_item_invalid"):
        save_first_pass(state, "unknown", decision, "now", allowed_item_ids=allowed)

    for item in snapshot.items:
        state = save_first_pass(
            state,
            item.opaque_id,
            decision,
            "now",
            expected_revision=state.revision,
            allowed_item_ids=allowed | {"extra"},
        )
    with pytest.raises(SessionError, match="label_cardinality_invalid"):
        save_first_pass(
            state,
            "extra",
            decision,
            "now",
            expected_revision=state.revision,
            allowed_item_ids=allowed | {"extra"},
        )


def test_runtime_maps_first_pass_validation_errors_to_stable_codes(tmp_path: Path) -> None:
    source, dataset_id = _fixture(tmp_path / "source")
    runtime = BlindLabelingRuntime(
        source,
        LabelingStore(tmp_path / "output", dataset_id=dataset_id, rubric_version=RUBRIC_VERSION),
        clock=lambda: "now",
    )
    runtime.start(runtime.status()["acknowledgement"])

    with pytest.raises(RuntimeErrorCode, match="pilot_item_invalid"):
        runtime.save_first_pass("unknown", Decision(Label.APPLY, "role_match"))
