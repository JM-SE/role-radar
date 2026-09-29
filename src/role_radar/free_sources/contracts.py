"""Frozen DTOs for free-source scheduling; no SQL, HTTP, or provider payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from role_radar.collectors.outcomes import CollectionOutcome


@dataclass(frozen=True, slots=True)
class FreeSourcePolicy:
    source_type: str
    source_key: str
    cadence_version: str
    policy_version: str
    cadence_seconds: int
    scheduled_only: bool = True


@dataclass(frozen=True, slots=True)
class DueSource:
    source_id: str
    source_type: str
    source_key: str
    name: str
    configuration: Mapping[str, Any]
    configuration_version: int
    due_slot: datetime


@dataclass(frozen=True, slots=True)
class ReservedFreeSource:
    source: DueSource
    reservation_id: str
    operation_id: str
    due_slot: datetime


@dataclass(frozen=True, slots=True)
class DeferredFreeSource:
    source_id: str
    source_key: str
    code: str
    due_slot: datetime | None = None


@dataclass(frozen=True, slots=True)
class FreeSourceTask:
    source: DueSource
    reservation_id: str | None
    operation_id: str | None
    deferred_code: str | None = None

    @property
    def due(self) -> bool:
        return True

    @property
    def reserved(self) -> bool:
        return self.reservation_id is not None and self.operation_id is not None


@dataclass(frozen=True, slots=True)
class FreeSourceExecution:
    task: FreeSourceTask
    outcome: CollectionOutcome | None
    attempted: bool
    deferred_code: str | None = None


@dataclass(frozen=True, slots=True)
class FreeSourceCounters:
    due: int = 0
    attempted: int = 0
    ok: int = 0
    failed: int = 0
    deferred: int = 0

    def __post_init__(self) -> None:
        if min(self.due, self.attempted, self.ok, self.failed, self.deferred) < 0:
            raise ValueError("free-source counters must be non-negative")

    @property
    def balanced(self) -> bool:
        return (
            self.due == self.attempted + self.deferred and self.attempted == self.ok + self.failed
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "due": self.due,
            "attempted": self.attempted,
            "ok": self.ok,
            "failed": self.failed,
            "deferred": self.deferred,
        }


@dataclass(frozen=True, slots=True)
class FreeSourcePlan:
    run_id: str
    tasks: tuple[FreeSourceTask, ...]
    counters: FreeSourceCounters
    scheduled: bool

    @property
    def reserved_tasks(self) -> tuple[FreeSourceTask, ...]:
        return tuple(task for task in self.tasks if task.reserved)


def sanitized_result(
    *,
    status: Literal["ok", "partial", "failed", "deferred"],
    counters: FreeSourceCounters,
    error_code: str | None = None,
    collected: int = 0,
    new_jobs: int = 0,
    duplicates: int = 0,
    prefiltered: int = 0,
    profile_rejected: int = 0,
    profile_reason_counts: dict[str, int] | None = None,
    clarification_attempts: int = 0,
) -> dict[str, Any]:
    """Project only stable counters/codes to the run journal."""
    result: dict[str, Any] = {
        "status": status,
        "due": counters.due,
        "attempted": counters.attempted,
        "ok": counters.ok,
        "failed": counters.failed,
        "deferred": counters.deferred,
        "collected": max(0, collected),
        "new_jobs": max(0, new_jobs),
        "duplicates": max(0, duplicates),
        "prefiltered": max(0, prefiltered),
        "profile_rejected": max(0, profile_rejected),
        "profile_reason_counts": dict(profile_reason_counts or {}),
        "clarification_attempts": max(0, clarification_attempts),
    }
    if error_code is not None:
        result["error_code"] = error_code
    return result
