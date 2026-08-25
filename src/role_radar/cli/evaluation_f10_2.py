"""Thin offline F10.2 CLI adapter."""
# ruff: noqa: E501

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from role_radar.evaluation.blind_labeling.interaction import (
    InteractionCancelled,
    InteractionError,
    StdTerminalIO,
    collect_decision,
    collect_review_decision,
)
from role_radar.evaluation.blind_labeling.pilot_source import PilotSource
from role_radar.evaluation.blind_labeling.policy import (
    DATASET_ID,
    EXIT_BLOCKED,
    EXIT_CANCELLED,
    EXIT_INTEGRITY,
    EXIT_INTERNAL,
    HEX64,
    OUTPUT_ROOT,
    SOURCE_ROOT,
)
from role_radar.evaluation.blind_labeling.review import review_items
from role_radar.evaluation.blind_labeling.runtime import BlindLabelingRuntime, RuntimeErrorCode
from role_radar.evaluation.blind_labeling.session import SessionError
from role_radar.evaluation.blind_labeling.store import LabelingStore, StoreError
from role_radar.evaluation.blind_labeling.validation import ValidationError, decision_dict


def _payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _runtime(dataset_id: str) -> BlindLabelingRuntime:
    if dataset_id != DATASET_ID:
        raise RuntimeErrorCode("dataset_id_mismatch")
    return BlindLabelingRuntime(
        PilotSource(Path(SOURCE_ROOT), dataset_id=dataset_id),
        LabelingStore(Path(OUTPUT_ROOT), dataset_id=dataset_id, rubric_version="f10.2-rubric-v1"),
    )


def _error_exit(code: str) -> int:
    if code in {
        "pilot_file_hash_mismatch",
        "pilot_file_changed",
        "pilot_file_unavailable",
        "draft_payload_tampered",
        "draft_schema_invalid",
        "draft_payload_invalid",
        "draft_read_failed",
        "stale_revision",
        "draft_state_invalid",
        "final_integrity_failed",
        "final_manifest_invalid",
        "final_checksum_mismatch",
        "final_checksum_invalid",
        "final_publish_failed",
        "final_conflict",
    }:
        return EXIT_INTEGRITY
    return EXIT_BLOCKED


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
            if HEX64.fullmatch(args.labelset_id) is None:
                raise RuntimeErrorCode("labelset_id_invalid")
            print(_payload(runtime.verify(args.labelset_id)))
            return 0
        io = StdTerminalIO(
            input,
            print,
            bool(sys.stdin.isatty() and sys.stdout.isatty()),
        )
        if not io.is_tty:
            print(_payload({"result": "cancelled", "code": "not_tty"}))
            return EXIT_CANCELLED
        if command == "label":
            snapshot = runtime.snapshot()
            state = runtime.state()
            while len(state.first_pass) < len(snapshot.items):
                for item in snapshot.items:
                    if item.opaque_id in dict(state.first_pass):
                        continue
                    decision = collect_decision(
                        io,
                        item,
                        index=len(dict(state.first_pass)) + 1,
                        total=len(snapshot.items),
                    )
                    runtime.save_first_pass(item.opaque_id, decision)
                    state = runtime.state()
            io.write(
                "Warning: canary checks are imperfect; the operator remains responsible for sensitive content.\n"
            )
            while True:
                revisit = io.read_line("Revisit item number (blank to finish): ").strip()
                if not revisit:
                    break
                try:
                    index = int(revisit)
                except ValueError as exc:
                    raise InteractionError("revisit_invalid") from exc
                if not 1 <= index <= len(snapshot.items):
                    raise InteractionError("revisit_invalid")
                item = snapshot.items[index - 1]
                runtime.save_first_pass(
                    item.opaque_id,
                    collect_decision(io, item, index=index, total=len(snapshot.items)),
                )
                state = runtime.state()
            print(_payload({"status": state.phase.value, "completed_count": len(state.first_pass)}))
            return 0
        if command == "review":
            runtime.begin_review()
            snapshot = runtime.snapshot()
            state = runtime.state()
            assert state.review_plan is not None
            plan = state.review_plan
            review_by_id = {item.item.opaque_id: item for item in review_items(snapshot, plan)}
            for item_id in plan.item_ids:
                state = runtime.state()
                if any(value.item_id == item_id for value in state.review_decisions):
                    continue
                decision = collect_review_decision(
                    io,
                    review_by_id[item_id],
                )
                runtime.save_review(item_id, decision)
            state = runtime.state()
            print(
                _payload(
                    {"status": state.phase.value, "reviewed_count": len(state.review_decisions)}
                )
            )
            return 0
        if command == "adjudicate":
            state = runtime.state()
            decisions = {
                item.item_id: item
                for item in state.review_decisions
                if not item.matches_first_pass
                and item.item_id not in {value.item_id for value in state.adjudications}
            }
            first = dict(state.first_pass)
            snapshot = runtime.snapshot()
            by_id = {item.opaque_id: item for item in snapshot.items}
            for item_id in decisions:
                io.write("\nAdjudicate discrepancy\n")
                io.write("First decision: " + _payload(decision_dict(first[item_id])) + "\n")
                io.write(
                    "Review decision: "
                    + _payload(decision_dict(decisions[item_id].decision))
                    + "\n"
                )
                # The adjudication prompt still collects a complete fresh decision.
                runtime.adjudicate(item_id, collect_decision(io, by_id[item_id], index=1, total=1))
            state = runtime.state()
            print(
                _payload(
                    {"status": state.phase.value, "adjudicated_count": len(state.adjudications)}
                )
            )
            return 0
        return 2
    except (RuntimeErrorCode, StoreError, SessionError, ValidationError, InteractionError) as exc:
        print(_payload({"result": "blocked", "code": getattr(exc, "code", "internal_error")}))
        return _error_exit(getattr(exc, "code", "internal_error"))
    except (EOFError, InteractionCancelled, KeyboardInterrupt):
        print(_payload({"result": "cancelled", "code": "cancelled"}))
        return EXIT_CANCELLED
    except Exception:
        print(_payload({"result": "blocked", "code": "internal_error"}))
        return EXIT_INTERNAL


__all__ = ["run"]
