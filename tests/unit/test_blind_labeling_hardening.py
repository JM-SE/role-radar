"""Regression tests for F10.2 Gate-A hardening boundaries."""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from role_radar.cli import evaluation_f10_2
from role_radar.evaluation.blind_labeling.contracts import (
    Adjudication,
    Decision,
    Label,
    PilotSnapshot,
    SessionPhase,
    SessionState,
)
from role_radar.evaluation.blind_labeling.filesystem import (
    FilesystemError,
    publish_no_replace,
)
from role_radar.evaluation.blind_labeling.materialization import build_bundle
from role_radar.evaluation.blind_labeling.pilot_source import PilotSourceError
from role_radar.evaluation.blind_labeling.policy import PROTOCOL_VERSION, RUBRIC_VERSION
from role_radar.evaluation.blind_labeling.runtime import BlindLabelingRuntime, RuntimeErrorCode
from role_radar.evaluation.blind_labeling.session import (
    SessionError,
    new_session,
    save_first_pass,
    save_review,
    seal_for_review,
)
from role_radar.evaluation.blind_labeling.store import LabelingStore, StoreError

from .test_blind_labeling_workflow import _fixture


def test_verify_route_uses_pinned_dataset_when_parser_omits_dataset_id(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeRuntime:
        def verify(self, labelset_id: str) -> dict[str, str]:
            assert labelset_id == "a" * 64
            return {"status": "verified"}

    monkeypatch.setattr(evaluation_f10_2, "_runtime", lambda dataset_id: FakeRuntime())
    args = SimpleNamespace(f10_2_command="verify", labelset_id="a" * 64)

    assert evaluation_f10_2.run(args) == 0
    assert capsys.readouterr().out == '{"status":"verified"}\n'


def test_cli_rejects_non_pinned_dataset_id(capsys: pytest.CaptureFixture[str]) -> None:
    args = SimpleNamespace(f10_2_command="status", dataset_id="e" * 64)

    assert evaluation_f10_2.run(args) == 3
    assert '"code":"dataset_id_mismatch"' in capsys.readouterr().out


def test_cli_verify_rejects_path_traversal(capsys: pytest.CaptureFixture[str]) -> None:
    args = SimpleNamespace(f10_2_command="verify", labelset_id="../outside")

    assert evaluation_f10_2.run(args) == 3
    assert '"code":"labelset_id_invalid"' in capsys.readouterr().out


def test_cli_interactive_commands_require_real_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeRuntime:
        pass

    class NonTty:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(evaluation_f10_2, "_runtime", lambda dataset_id: FakeRuntime())
    monkeypatch.setattr(sys, "stdin", NonTty())
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


def test_pilot_source_opens_no_holdout_or_sibling_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source, _dataset_id = _fixture(tmp_path / "source")
    original_open = os.open
    opened: list[str] = []

    def tracking_open(
        path: os.PathLike[str] | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if isinstance(path, (str, bytes)):
            opened.append(os.fsdecode(path))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", tracking_open)
    source.load()

    assert all("holdout-label-view.jsonl" not in path for path in opened)
    assert all("internal-manifest.json" not in path for path in opened)

    source, _ = _fixture(tmp_path / "source-2")
    source.path.parent.chmod(0o755)
    with pytest.raises(PilotSourceError, match="pilot_directory_mode"):
        source.load()


def test_publish_no_replace_never_overwrites_existing_target(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.mkdir(mode=0o700)
    (staging / "payload").write_bytes(b"new")
    target.mkdir(mode=0o700)
    (target / "payload").write_bytes(b"old")

    with pytest.raises(FilesystemError, match="publish_conflict"):
        publish_no_replace(staging, target)

    assert (target / "payload").read_bytes() == b"old"
    assert (staging / "payload").read_bytes() == b"new"


def test_publish_no_replace_publishes_new_target_atomically(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.mkdir(mode=0o700)
    (staging / "payload").write_bytes(b"new")

    publish_no_replace(staging, target)

    assert (target / "payload").read_bytes() == b"new"
    assert not staging.exists()


def test_first_pass_rejects_unknown_item_and_more_than_pilot_cardinality(tmp_path: Path) -> None:
    source, _ = _fixture(tmp_path / "source")
    snapshot = source.load()
    state = new_session(snapshot, RUBRIC_VERSION, "b" * 64, PROTOCOL_VERSION, "now")
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


def test_store_rejects_impossible_persisted_phase(tmp_path: Path) -> None:
    source, dataset_id = _fixture(tmp_path / "source")
    state = new_session(source.load(), RUBRIC_VERSION, "b" * 64, PROTOCOL_VERSION, "now")
    impossible = replace(state, phase=SessionPhase.READY_TO_FINALIZE)
    store = LabelingStore(tmp_path / "output", dataset_id=dataset_id, rubric_version=RUBRIC_VERSION)

    with pytest.raises(StoreError, match="draft_phase_invalid"):
        store.create(impossible)


def test_store_does_not_report_empty_draft_as_existing(tmp_path: Path) -> None:
    _source, dataset_id = _fixture(tmp_path / "source")
    store = LabelingStore(tmp_path / "output", dataset_id=dataset_id, rubric_version=RUBRIC_VERSION)
    store.draft_root.mkdir(mode=0o700, parents=True)

    assert not store.exists()


def test_final_verification_rejects_duplicate_checksum_names(tmp_path: Path) -> None:
    source, dataset_id = _fixture(tmp_path / "source")
    store = LabelingStore(tmp_path / "output", dataset_id=dataset_id, rubric_version=RUBRIC_VERSION)
    runtime = BlindLabelingRuntime(source, store, clock=lambda: "now")
    runtime.start(runtime.status()["acknowledgement"])
    for item in source.load().items:
        runtime.save_first_pass(item.opaque_id, Decision(Label.APPLY, "role_match"))
    runtime.begin_review()
    for item_id in runtime._state().review_plan.item_ids:  # type: ignore[union-attr]
        runtime.save_review(item_id, Decision(Label.APPLY, "role_match"))
    labelset_id = runtime.finalize(runtime.preview_finalize()["challenge"]).labelset_id
    checksums = store.session_root / "final" / labelset_id / "checksums.sha256"
    first_line = checksums.read_text(encoding="ascii").splitlines()[0]
    checksums.write_text("\n".join([first_line] * 5) + "\n", encoding="ascii")

    assert not store.verify_final(labelset_id)


def test_labelset_identity_is_invariant_to_cross_item_interaction_order(tmp_path: Path) -> None:
    source, _dataset_id = _fixture(tmp_path / "source")
    snapshot = source.load()

    def materialize(order: tuple[str, ...]) -> str:
        state = new_session(snapshot, RUBRIC_VERSION, "b" * 64, PROTOCOL_VERSION, "now")
        for item_id in order:
            state = save_first_pass(
                state,
                item_id,
                Decision(Label.APPLY, "role_match"),
                "now",
                expected_revision=state.revision,
            )
        state = seal_for_review(state, snapshot, "now")
        for item_id in state.review_plan.item_ids:  # type: ignore[union-attr]
            state = save_review(
                state,
                item_id,
                Decision(Label.APPLY, "role_match"),
                "now",
                expected_revision=state.revision,
            )
        return build_bundle(snapshot, state, "now")[2]

    ids = tuple(item.opaque_id for item in snapshot.items)
    assert materialize(ids) == materialize(tuple(reversed(ids)))


def test_cli_adjudication_serializes_private_decisions_without_internal_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    source, _dataset_id = _fixture(tmp_path / "source")
    snapshot = source.load()
    state = new_session(snapshot, RUBRIC_VERSION, "b" * 64, PROTOCOL_VERSION, "now")
    for item in snapshot.items:
        state = save_first_pass(
            state,
            item.opaque_id,
            Decision(Label.APPLY, "role_match"),
            "now",
            expected_revision=state.revision,
        )
    state = seal_for_review(state, snapshot, "now")
    for index, item_id in enumerate(state.review_plan.item_ids):  # type: ignore[union-attr]
        decision = (
            Decision(Label.REJECT, "role_mismatch")
            if index == 0
            else Decision(Label.APPLY, "role_match")
        )
        state = save_review(state, item_id, decision, "now", expected_revision=state.revision)
    discrepancy_id = next(
        item.item_id for item in state.review_decisions if not item.matches_first_pass
    )

    class FakeIO:
        is_tty = True

        def __init__(self) -> None:
            self.answers = iter(("apply", "role_match", "", "", "y"))

        def read_line(self, _prompt: str) -> str:
            return next(self.answers)

        def write(self, _value: str) -> None:
            return None

    class FakeRuntime:
        def __init__(self) -> None:
            self.current = state

        def state(self) -> SessionState:
            return self.current

        def snapshot(self) -> PilotSnapshot:
            return snapshot

        def adjudicate(self, item_id: str, decision: Decision) -> dict[str, object]:
            assert item_id == discrepancy_id
            self.current = replace(
                self.current,
                phase=SessionPhase.READY_TO_FINALIZE,
                adjudications=(Adjudication(item_id, decision),),
            )
            return {"status": "ready_to_finalize", "adjudicated_count": 1}

    runtime = FakeRuntime()
    io = FakeIO()
    monkeypatch.setattr(evaluation_f10_2, "_runtime", lambda _dataset_id: runtime)
    monkeypatch.setattr(evaluation_f10_2, "StdTerminalIO", lambda *_args: io)

    args = SimpleNamespace(f10_2_command="adjudicate")
    assert evaluation_f10_2.run(args) == 0
    output = capsys.readouterr().out
    assert '"adjudicated_count":1' in output
    assert "internal_error" not in output
