"""Synthetic end-to-end F10.2 Gate-A workflow tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from role_radar.evaluation.blind_labeling.contracts import Decision, Label
from role_radar.evaluation.blind_labeling.materialization import build_bundle
from role_radar.evaluation.blind_labeling.pilot_source import PilotSource
from role_radar.evaluation.blind_labeling.policy import PROTOCOL_VERSION, RUBRIC_VERSION
from role_radar.evaluation.blind_labeling.review import review_items
from role_radar.evaluation.blind_labeling.runtime import BlindLabelingRuntime
from role_radar.evaluation.blind_labeling.session import (
    new_session,
    save_first_pass,
    save_review,
    seal_for_review,
)
from role_radar.evaluation.blind_labeling.store import LabelingStore
from role_radar.evaluation.blind_labeling.validation import canonical_line


def _fixture(root: Path) -> tuple[PilotSource, str]:
    dataset_id = "d" * 64
    directory = root / dataset_id
    directory.mkdir(mode=0o700, parents=True)
    os.chmod(root, 0o700)
    lines = tuple(
        canonical_line(
            {
                "opaque_id": f"{index:024x}",
                "title": f"Role {index}",
                "company": "Acme",
                "location": None,
                "description": "A role description.",
            }
        )
        for index in range(50)
    )
    payload = b"".join(lines)
    path = directory / "pilot-label-view.jsonl"
    path.write_bytes(payload)
    os.chmod(path, 0o600)
    file_hash = hashlib.sha256(payload).hexdigest()
    return (
        PilotSource(
            root,
            dataset_id=dataset_id,
            pilot_sha256="p" * 64,
            pilot_file_sha256=file_hash,
        ),
        dataset_id,
    )


def test_full_first_pass_review_and_immutable_materialization(tmp_path: Path) -> None:
    source, dataset_id = _fixture(tmp_path / "source")
    snapshot = source.load()
    state = new_session(
        snapshot,
        RUBRIC_VERSION,
        "r" * 64,
        PROTOCOL_VERSION,
        "2026-01-01T00:00:00Z",
    )
    for item in snapshot.items:
        state = save_first_pass(
            state,
            item.opaque_id,
            Decision(Label.APPLY, "role_match"),
            "2026-01-01T00:00:00Z",
            expected_revision=state.revision,
        )
    state = seal_for_review(state, snapshot, "2026-01-01T00:00:00Z")
    assert state.review_plan is not None
    assert len(review_items(snapshot, state.review_plan)) == 10
    for item_id in state.review_plan.item_ids:
        state = save_review(
            state,
            item_id,
            Decision(Label.APPLY, "role_match"),
            "2026-01-01T00:00:00Z",
            expected_revision=state.revision,
        )
    payloads, internal, labelset_id = build_bundle(snapshot, state, "2026-01-01T00:00:00Z")
    assert len(payloads["labels.jsonl"].splitlines()) == 50
    assert internal["labelset_id"] == labelset_id

    store = LabelingStore(
        tmp_path / "output", dataset_id=dataset_id, rubric_version=RUBRIC_VERSION
    )
    store.create(
        new_session(
            snapshot,
            RUBRIC_VERSION,
            "r" * 64,
            PROTOCOL_VERSION,
            "2026-01-01T00:00:00Z",
        )
    )
    assert store.exists()


def test_runtime_finalization_retry_is_idempotent(tmp_path: Path) -> None:
    source, dataset_id = _fixture(tmp_path / "source")
    store = LabelingStore(
        tmp_path / "output", dataset_id=dataset_id, rubric_version=RUBRIC_VERSION
    )
    runtime = BlindLabelingRuntime(
        source,
        store,
        clock=lambda: "2026-01-01T00:00:00Z",
    )
    start = runtime.status()["acknowledgement"]
    runtime.start(start)
    for item in source.load().items:
        runtime.save_first_pass(item.opaque_id, Decision(Label.APPLY, "role_match"))
    runtime.begin_review()
    state = runtime._state()
    assert state.review_plan is not None
    for item_id in state.review_plan.item_ids:
        runtime.save_review(item_id, Decision(Label.APPLY, "role_match"))
    challenge = runtime.preview_finalize()["challenge"]
    first = runtime.finalize(challenge)
    second = runtime.finalize(challenge)
    assert first.labelset_id == second.labelset_id
    assert runtime.verify(first.labelset_id)["status"] == "verified"
