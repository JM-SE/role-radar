"""Pure authorization contract for the read-only recovered Gate E preflight."""

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

ACTION: Final = "offline_recovered_gate_e_preflight"
EXPECTED_APPROVAL_REFERENCE: Final = "r2-gate-e-preflight-20260912-001"
EXPECTED_GATE_D_ROOT: Final = "/home/jmse/r2-evidence/r2-gate-d-20260912-001"
EXPECTED_GATE_D_MANIFEST_SHA256: Final = (
    "ffe183ed040d6a090ff33b6ab0743a1cd5df33c384ad9e810847ebe3381b88fd"
)
EXPECTED_CANDIDATE_COMMIT_SHA256: Final = "734f5c08f23a3e2a97032c54cabef0f324a2bf94"
_HEX40 = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class RecoveredGateEPreflightAuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveredGateEPreflightAuthorization:
    action: str
    approval_reference: str
    candidate_commit_sha256: str
    window_start_utc: str
    expires_at_utc: str
    historical_root: str
    recovery_root: str
    post_c_root: str
    gate_d_root: str
    operation_id: str
    seal_sha256: str
    source_plan_sha256: str
    report_sha256: str
    post_c_authorization_sha256: str
    gate_d_manifest_sha256: str
    source_keys: tuple[str, ...]
    clock: Callable[[], datetime]

    def __post_init__(self) -> None:
        if self.action != ACTION:
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_action_invalid")
        if (
            type(self.approval_reference) is not str
            or self.approval_reference != EXPECTED_APPROVAL_REFERENCE
        ):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_approval_invalid")
        if type(self.candidate_commit_sha256) is not str or not _HEX40.fullmatch(
            self.candidate_commit_sha256
        ):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_commit_invalid")
        roots = (
            self.historical_root,
            self.recovery_root,
            self.post_c_root,
            self.gate_d_root,
        )
        if any(
            type(root) is not str or not Path(root).is_absolute() or ".." in Path(root).parts
            for root in roots
        ):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_root_invalid")
        if roots != (
            EXPECTED_HISTORICAL_ROOT,
            EXPECTED_RECOVERY_ROOT,
            EXPECTED_POST_C_ROOT,
            EXPECTED_GATE_D_ROOT,
        ):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_anchor_mismatch")
        parsed_roots = tuple(Path(root) for root in roots)
        if any(
            left == right or left in right.parents or right in left.parents
            for index, left in enumerate(parsed_roots)
            for right in parsed_roots[index + 1 :]
        ):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_roots_overlap")
        if self.operation_id != EXPECTED_OPERATION_ID:
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_anchor_mismatch")
        hashes = (
            self.seal_sha256,
            self.source_plan_sha256,
            self.report_sha256,
            self.post_c_authorization_sha256,
            self.gate_d_manifest_sha256,
        )
        if any(type(value) is not str or not _HEX64.fullmatch(value) for value in hashes):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_anchor_invalid")
        if (
            hashes
            != (
                EXPECTED_SEAL_SHA256,
                EXPECTED_SOURCE_PLAN_SHA256,
                EXPECTED_REPORT_SHA256,
                EXPECTED_POST_C_AUTHORIZATION_SHA256,
                EXPECTED_GATE_D_MANIFEST_SHA256,
            )
            or self.candidate_commit_sha256 != EXPECTED_CANDIDATE_COMMIT_SHA256
        ):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_anchor_mismatch")
        if type(self.source_keys) is not tuple or self.source_keys != EXPECTED_SOURCE_KEYS:
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_sources_invalid")
        if not callable(self.clock):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_clock_invalid")
        start = _parse_utc(self.window_start_utc)
        end = _parse_utc(self.expires_at_utc)
        if not start < end:
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_window_invalid")

    def validate_current(self, now: datetime) -> None:
        if type(now) is not datetime or now.tzinfo is not UTC:
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_clock_invalid")
        if not _parse_utc(self.window_start_utc) <= now < _parse_utc(self.expires_at_utc):
            raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_expired")


def _parse_utc(value: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_window_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_window_invalid") from exc
    if parsed.tzinfo is not UTC:
        raise RecoveredGateEPreflightAuthorizationError("gate_e_preflight_window_invalid")
    return parsed


__all__ = [
    "ACTION",
    "EXPECTED_APPROVAL_REFERENCE",
    "EXPECTED_CANDIDATE_COMMIT_SHA256",
    "EXPECTED_GATE_D_MANIFEST_SHA256",
    "EXPECTED_GATE_D_ROOT",
    "RecoveredGateEPreflightAuthorization",
    "RecoveredGateEPreflightAuthorizationError",
]
