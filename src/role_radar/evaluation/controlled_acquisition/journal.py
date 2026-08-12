"""Small private filesystem journal with atomic replace and no raw errors."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from role_radar.evaluation.controlled_acquisition.contracts import OperationState
from role_radar.evaluation.controlled_acquisition.protocols import JOURNAL_VERSION


@dataclass(frozen=True, slots=True)
class JournalEvent:
    kind: str
    code: str
    state: str
    details: dict[str, Any]


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)

    def read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": JOURNAL_VERSION, "events": []}
        return cast(dict[str, Any], json.loads(self.path.read_text(encoding="utf-8")))

    def append(self, event: JournalEvent) -> None:
        current = self.read()
        current.setdefault("events", []).append(
            {
                "kind": event.kind,
                "code": event.code,
                "state": event.state,
                "details": event.details,
            }
        )
        payload = json.dumps(current, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def has_pending_request(self, operation_id: str) -> bool:
        events = self.read().get("events", [])
        intents = {
            event.get("details", {}).get("request_id")
            for event in events
            if event.get("kind") == "request_intent"
            and event.get("details", {}).get("operation_id") == operation_id
        }
        results = {
            event.get("details", {}).get("request_id")
            for event in events
            if event.get("kind") == "request_result"
            and event.get("details", {}).get("operation_id") == operation_id
        }
        return bool(intents - results)

    def record_request_intent(self, *, operation_id: str, request_id: str) -> None:
        self.append(
            JournalEvent(
                "request_intent",
                "collector_request",
                OperationState.ACQUIRING.value,
                {"operation_id": operation_id, "request_id": request_id},
            )
        )

    def record_request_result(self, *, operation_id: str, request_id: str) -> None:
        self.append(
            JournalEvent(
                "request_result",
                "collector_completed",
                OperationState.ACQUIRING.value,
                {"operation_id": operation_id, "request_id": request_id},
            )
        )


VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    OperationState.PLANNED: frozenset({OperationState.PLAN_APPROVED, OperationState.ABORTED}),
    OperationState.PLAN_APPROVED: frozenset({OperationState.ACQUIRING, OperationState.ABORTED}),
    OperationState.ACQUIRING: frozenset(
        {OperationState.POOL_SEALED, OperationState.FAILED, OperationState.INDETERMINATE}
    ),
    OperationState.POOL_SEALED: frozenset({OperationState.SELECTED, OperationState.FAILED}),
    OperationState.SELECTED: frozenset({OperationState.STAGED, OperationState.FAILED}),
    OperationState.STAGED: frozenset({OperationState.VERIFIED, OperationState.FAILED}),
    OperationState.VERIFIED: frozenset({OperationState.PUBLISHED, OperationState.FAILED}),
    OperationState.PUBLISHED: frozenset({OperationState.COMPLETED}),
    OperationState.COMPLETED: frozenset(),
    OperationState.FAILED: frozenset(),
    OperationState.INDETERMINATE: frozenset(),
    OperationState.ABORTED: frozenset(),
}


def validate_transition(current: str, next_state: str) -> None:
    if next_state not in VALID_TRANSITIONS.get(current, frozenset()):
        raise ValueError("invalid_operation_transition")
