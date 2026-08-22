"""Thin offline F10.2 CLI adapter."""
# ruff: noqa: E501

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from role_radar.evaluation.blind_labeling.interaction import (
    InteractionCancelled,
    StdTerminalIO,
    collect_decision,
    collect_review_decision,
)
from role_radar.evaluation.blind_labeling.pilot_source import PilotSource
from role_radar.evaluation.blind_labeling.policy import DATASET_ID, OUTPUT_ROOT, SOURCE_ROOT
from role_radar.evaluation.blind_labeling.runtime import BlindLabelingRuntime, RuntimeErrorCode
from role_radar.evaluation.blind_labeling.store import LabelingStore, StoreError


def _payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _runtime(dataset_id: str) -> BlindLabelingRuntime:
    if dataset_id != DATASET_ID:
        raise RuntimeErrorCode("dataset_id_mismatch")
    return BlindLabelingRuntime(
        PilotSource(Path(SOURCE_ROOT), dataset_id=dataset_id),
        LabelingStore(Path(OUTPUT_ROOT), dataset_id=dataset_id, rubric_version="f10.2-rubric-v1"),
    )


def run(args: Any) -> int:
    dataset_id = getattr(args, "dataset_id", DATASET_ID)
    try:
        if dataset_id != DATASET_ID:
            raise RuntimeErrorCode("dataset_id_mismatch")
        runtime = _runtime(dataset_id)
        command = args.f10_2_command
        if command == "status":
            print(_payload(runtime.status()))
            return 0
        if command == "start":
            print(_payload(runtime.start(args.acknowledgement)))
            return 0
        if command == "reopen-first-pass":
            print(_payload(runtime.reopen(args.acknowledgement)))
            return 0
        if command == "preview-finalize":
            print(_payload(runtime.preview_finalize()))
            return 0
        if command == "finalize":
            print(_payload(runtime.finalize(args.acknowledgement).external_manifest))
            return 0
        if command == "verify":
            print(_payload(_runtime(DATASET_ID).verify(args.labelset_id)))
            return 0
        io = StdTerminalIO(
            input,
            print,
            bool(sys.stdin.isatty() and sys.stdout.isatty()),
        )
        if not io.is_tty:
            return 130
        if command == "label":
            snapshot = runtime._snapshot()  # injected CLI composition boundary
            state = runtime._state()
            for item in snapshot.items:
                if item.opaque_id in dict(state.first_pass):
                    continue
                decision = collect_decision(io, item, index=len(dict(state.first_pass)) + 1, total=len(snapshot.items))
                runtime.save_first_pass(item.opaque_id, decision)
                state = runtime._state()
            print(_payload({"status": state.phase.value, "completed_count": len(state.first_pass)}))
            return 0
        if command == "review":
            runtime.begin_review()
            snapshot = runtime._snapshot()
            state = runtime._state()
            assert state.review_plan is not None
            plan = state.review_plan
            by_id = {item.opaque_id: item for item in snapshot.items}
            for index, item_id in enumerate(plan.item_ids, start=1):
                state = runtime._state()
                if any(value.item_id == item_id for value in state.review_decisions):
                    continue
                decision = collect_review_decision(
                    io,
                    type(
                        "Review",
                        (),
                        {"index": index, "total": len(plan.item_ids), "item": by_id[item_id]},
                    )(),
                )
                runtime.save_review(item_id, decision)
            state = runtime._state()
            print(_payload({"status": state.phase.value, "reviewed_count": len(state.review_decisions)}))
            return 0
        if command == "adjudicate":
            state = runtime._state()
            decisions = {item.item_id: item for item in state.review_decisions if not item.matches_first_pass and item.item_id not in {value.item_id for value in state.adjudications}}
            first = dict(state.first_pass)
            for item_id in decisions:
                io.write(f"\nAdjudicate item {item_id}\n")
                io.write("First decision: " + _payload(first[item_id]) + "\n")
                io.write("Review decision: " + _payload(decisions[item_id].decision) + "\n")
                # The adjudication prompt still collects a complete fresh decision.
                item = runtime._snapshot().items[[value.opaque_id for value in runtime._snapshot().items].index(item_id)]
                runtime.adjudicate(item_id, collect_decision(io, item, index=1, total=1))
            state = runtime._state()
            print(_payload({"status": state.phase.value, "adjudicated_count": len(state.adjudications)}))
            return 0
        return 2
    except (RuntimeErrorCode, StoreError) as exc:
        print(_payload({"result": "blocked", "code": getattr(exc, "code", "internal_error")}))
        return 3 if getattr(exc, "code", "").endswith(("mismatch", "missing", "incomplete", "invalid", "not_ready")) else 4
    except (EOFError, InteractionCancelled, KeyboardInterrupt):
        print(_payload({"result": "cancelled", "code": "cancelled"}))
        return 130
    except Exception:
        print(_payload({"result": "blocked", "code": "internal_error"}))
        return 70


__all__ = ["run"]
