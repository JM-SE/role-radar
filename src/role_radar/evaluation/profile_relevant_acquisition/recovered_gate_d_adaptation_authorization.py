"""Pure authorization for the recovered ``completed_partial`` Gate D seam."""

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

ACTION: Final = "offline_recovered_gate_d_compatibility"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class RecoveredGateDAdaptationAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveredGateDAdaptationAuthorization:
    action: str
    approval_reference: str
    operator_id: str
    window_start_utc: str
    expires_at_utc: str
    historical_root: str
    recovery_root: str
    post_c_root: str
    operation_id: str
    seal_sha256: str
    source_plan_sha256: str
    report_sha256: str
    post_c_authorization_sha256: str
    source_keys: tuple[str, ...]
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        if self.action != ACTION:
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_action_invalid")
        if (
            type(self.approval_reference) is not str
            or not self.approval_reference.strip()
            or self.approval_reference == "r2-gate-c-20260911"
        ):
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_approval_invalid")
        if type(self.operator_id) is not str or not self.operator_id.strip():
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_operator_invalid")
        roots = (self.historical_root, self.recovery_root, self.post_c_root)
        if any(type(value) is not str or not Path(value).is_absolute() for value in roots):
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_root_invalid")
        if roots != (EXPECTED_HISTORICAL_ROOT, EXPECTED_RECOVERY_ROOT, EXPECTED_POST_C_ROOT):
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_anchor_mismatch")
        if self.operation_id != EXPECTED_OPERATION_ID:
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_anchor_mismatch")
        for value in (
            self.seal_sha256,
            self.source_plan_sha256,
            self.report_sha256,
            self.post_c_authorization_sha256,
        ):
            if type(value) is not str or _HEX64.fullmatch(value) is None:
                raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_anchor_invalid")
        if (
            self.seal_sha256 != EXPECTED_SEAL_SHA256
            or self.source_plan_sha256 != EXPECTED_SOURCE_PLAN_SHA256
            or self.report_sha256 != EXPECTED_REPORT_SHA256
            or self.post_c_authorization_sha256 != EXPECTED_POST_C_AUTHORIZATION_SHA256
            or self.source_keys != EXPECTED_SOURCE_KEYS
        ):
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_anchor_mismatch")
        if type(self.source_keys) is not tuple or len(self.source_keys) != 6:
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_sources_invalid")
        if not callable(self.clock):
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_clock_invalid")
        _parse_utc(self.window_start_utc)
        _parse_utc(self.expires_at_utc)
        if _parse_utc(self.window_start_utc) >= _parse_utc(self.expires_at_utc):
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_window_invalid")

    def validate_current(self, now: datetime) -> None:
        if type(now) is not datetime or now.tzinfo is not UTC:
            raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_clock_invalid")
        if not _parse_utc(self.window_start_utc) <= now < _parse_utc(self.expires_at_utc):
            raise RecoveredGateDAdaptationAuthorizationError(
                "recovered_gate_d_authorization_expired"
            )


def _parse_utc(value: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_window_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_window_invalid") from exc
    if parsed.tzinfo is not UTC:
        raise RecoveredGateDAdaptationAuthorizationError("recovered_gate_d_window_invalid")
    return parsed


__all__ = [
    "ACTION",
    "RecoveredGateDAdaptationAuthorization",
    "RecoveredGateDAdaptationAuthorizationError",
]
