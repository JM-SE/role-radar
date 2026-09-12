"""Pure authorization contract for the recovered bounded synthetic Gate D path."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from .recovered_gate_d_authorization import (
    EXPECTED_HISTORICAL_ROOT,
    EXPECTED_OPERATION_ID,
    EXPECTED_POST_C_AUTHORIZATION_SHA256,
    EXPECTED_POST_C_ROOT,
    EXPECTED_RECOVERY_ROOT,
    EXPECTED_REPORT_SHA256,
    EXPECTED_SEAL_SHA256,
    EXPECTED_SOURCE_KEYS,
    EXPECTED_SOURCE_PLAN_SHA256,
)

ACTION: Final = "offline_recovered_bounded_synthetic_acquisition"
EXPECTED_COMMIT_SHA256: Final = "734f5c08f23a3e2a97032c54cabef0f324a2bf94"
EXPECTED_APPROVAL_REFERENCE: Final = "r2-gate-d-20260912-001"
EXPECTED_OPERATOR_ID: Final = "jmse"
EXPECTED_WINDOW_START_UTC: Final = "2026-09-12T00:00:00Z"
EXPECTED_EXPIRES_AT_UTC: Final = "2026-09-13T00:00:00Z"
EXPECTED_OUTPUT_ROOT: Final = "/home/jmse/r2-evidence/r2-gate-d-20260912-001"
_HEX40 = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class RecoveredGateDExecutionAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveredGateDExecutionAuthorization:
    action: str
    approval_reference: str
    operator_id: str
    candidate_commit_sha256: str
    window_start_utc: str
    expires_at_utc: str
    historical_root: str
    recovery_root: str
    post_c_root: str
    output_root: str
    operation_id: str
    seal_sha256: str
    source_plan_sha256: str
    report_sha256: str
    post_c_authorization_sha256: str
    source_keys: tuple[str, ...]
    namespace: str
    selection_seed: str
    partition_seed: str
    budget_units: int
    max_parent_pool: int
    max_journal_entries: int
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        if self.action != ACTION:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_action_invalid")
        if type(self.approval_reference) is not str or not self.approval_reference.strip():
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_approval_invalid")
        if type(self.operator_id) is not str or not self.operator_id.strip():
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_operator_invalid")
        if (
            self.approval_reference != EXPECTED_APPROVAL_REFERENCE
            or self.operator_id != EXPECTED_OPERATOR_ID
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_mismatch")
        roots = (
            self.historical_root,
            self.recovery_root,
            self.post_c_root,
            self.output_root,
        )
        if any(
            type(root) is not str or not Path(root).is_absolute() or ".." in Path(root).parts
            for root in roots
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_root_invalid")
        if roots[:3] != (
            EXPECTED_HISTORICAL_ROOT,
            EXPECTED_RECOVERY_ROOT,
            EXPECTED_POST_C_ROOT,
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_mismatch")
        if self.output_root != EXPECTED_OUTPUT_ROOT:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_mismatch")
        parsed_roots = tuple(Path(root) for root in roots)
        if any(
            left == right or left in right.parents or right in left.parents
            for index, left in enumerate(parsed_roots)
            for right in parsed_roots[index + 1 :]
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_roots_overlap")
        if self.operation_id != EXPECTED_OPERATION_ID:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_mismatch")
        if _HEX40.fullmatch(self.candidate_commit_sha256) is None:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_invalid")
        for value in (
            self.seal_sha256,
            self.source_plan_sha256,
            self.report_sha256,
            self.post_c_authorization_sha256,
        ):
            if type(value) is not str or _HEX64.fullmatch(value) is None:
                raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_invalid")
        if self.candidate_commit_sha256 != EXPECTED_COMMIT_SHA256 or (
            self.seal_sha256,
            self.source_plan_sha256,
            self.report_sha256,
            self.post_c_authorization_sha256,
        ) != (
            EXPECTED_SEAL_SHA256,
            EXPECTED_SOURCE_PLAN_SHA256,
            EXPECTED_REPORT_SHA256,
            EXPECTED_POST_C_AUTHORIZATION_SHA256,
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_mismatch")
        if type(self.source_keys) is not tuple or self.source_keys != EXPECTED_SOURCE_KEYS:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_sources_invalid")
        if any(
            type(value) is not str or not value.strip()
            for value in (self.namespace, self.selection_seed, self.partition_seed)
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_synthetic_invalid")
        if any(
            type(value) is not int or not 1 <= value <= 1000
            for value in (self.budget_units, self.max_parent_pool, self.max_journal_entries)
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_limits_invalid")
        if not callable(self.clock):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_clock_invalid")
        start = _parse_utc(self.window_start_utc)
        end = _parse_utc(self.expires_at_utc)
        if not start < end:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_window_invalid")
        if (
            self.window_start_utc != EXPECTED_WINDOW_START_UTC
            or self.expires_at_utc != EXPECTED_EXPIRES_AT_UTC
        ):
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_anchor_mismatch")

    def validate_current(self, now: datetime) -> None:
        if type(now) is not datetime or now.tzinfo is not UTC:
            raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_clock_invalid")
        if not _parse_utc(self.window_start_utc) <= now < _parse_utc(self.expires_at_utc):
            raise RecoveredGateDExecutionAuthorizationError(
                "gate_d_execution_authorization_expired"
            )


def _parse_utc(value: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_window_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_window_invalid") from exc
    if parsed.tzinfo is not UTC:
        raise RecoveredGateDExecutionAuthorizationError("gate_d_execution_window_invalid")
    return parsed


__all__ = [
    "ACTION",
    "RecoveredGateDExecutionAuthorization",
    "RecoveredGateDExecutionAuthorizationError",
]
