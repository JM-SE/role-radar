"""Pure authorization boundary for the read-only recovered Gate D preflight."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

HEX64: Final = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
ACTION: Final = "offline_compatibility_preflight"
EXPECTED_HISTORICAL_ROOT: Final = "/home/jmse/r2-evidence/r2-discover-20260911-clean-024003"
EXPECTED_RECOVERY_ROOT: Final = "/home/jmse/r2-evidence/r2-discover-20260911-recovered-024003"
EXPECTED_POST_C_ROOT: Final = "/home/jmse/r2-evidence/r2-post-c-20260912-001"
EXPECTED_OPERATION_ID: Final = "ca3fbc4d-7f8e-49a6-8263-c1fdd69bbad5"
EXPECTED_OPERATION_SHA256: Final = (
    "6233bfc55cd8568d0c981dcab4ce10b6121f31d1721734cd886eebf4f780f749"
)
EXPECTED_PLAN_SHA256: Final = "e7ea8287e7cb1d1d4f2f32ffb8c0db84b1889bf70be404a96778b34a9afc2b95"
EXPECTED_EVIDENCE_SHA256: Final = "11a6283a0026e19fc0275f45ac47da34894c91a9e0b8d051a9b5e4a7cebadd4c"
EXPECTED_POLICY_SHA256: Final = "387ed6fa43c2be8001cf10a1b1fb645eead6f6cecefb606e450d53bd016f1cc0"
EXPECTED_PROFILE_ID: Final = "818eded4-2f69-4e66-ad12-cd0749e4ab3e"
EXPECTED_PROFILE_SHA256: Final = "2a01d22969d3a8811a3816adba699ffad3e2946ae2e54527e0495c63cc467918"
EXPECTED_PROFILE_VERSION: Final = 2
EXPECTED_HISTORICAL_APPROVAL: Final = "r2-gate-c-20260911"
EXPECTED_POST_C_APPROVAL: Final = "r2-post-c-20260912-001"
EXPECTED_STATE: Final = "completed_partial"
EXPECTED_TERMINAL_CODE: Final = "multiple_budgets_exhausted"
EXPECTED_WINDOW_START_UTC: Final = "2026-09-12T00:00:00Z"
EXPECTED_EXPIRES_AT_UTC: Final = "2026-09-13T00:00:00Z"
EXPECTED_SEAL_SHA256: Final = "2c5e7a867d1c06eeaf5720e2e04ca95f2af862a91b0a0e86d10e3fb0c6bf322d"
EXPECTED_SOURCE_PLAN_SHA256: Final = (
    "def7b57e24be9eb0f360c4b06ede67de9f71e105657afad8efc8820b69dd9846"
)
EXPECTED_REPORT_SHA256: Final = "3f816b91d078e9f91ed78422f44189d61f265dee582a1daa4387337638817de0"
EXPECTED_POST_C_AUTHORIZATION_SHA256: Final = (
    "9e10082c0b4d8c69cef5ff21922540c319c22874eed7b8d8849a5af9722a1289"
)
EXPECTED_SOURCE_KEYS: Final = (
    "greenhouse:twilio",
    "greenhouse:grafanalabs",
    "greenhouse:similarweb",
    "greenhouse:stackline",
    "greenhouse:postman",
    "greenhouse:figma",
)


class RecoveredGateDPreflightError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecoveredGateDPreflightAuthorization:
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
            raise RecoveredGateDPreflightError("gate_d_preflight_action_invalid")
        if type(self.approval_reference) is not str or not self.approval_reference.strip():
            raise RecoveredGateDPreflightError("gate_d_preflight_authorization_invalid")
        if type(self.operator_id) is not str or not self.operator_id.strip():
            raise RecoveredGateDPreflightError("gate_d_preflight_authorization_invalid")
        values = (self.historical_root, self.recovery_root, self.post_c_root)
        roots = tuple(Path(value) for value in values if type(value) is str)
        if len(roots) != 3 or any(not root.is_absolute() or ".." in root.parts for root in roots):
            raise RecoveredGateDPreflightError("gate_d_preflight_root_invalid")
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(roots)
            for b in roots[i + 1 :]
        ):
            raise RecoveredGateDPreflightError("gate_d_preflight_roots_overlap")
        for value in (
            self.seal_sha256,
            self.source_plan_sha256,
            self.report_sha256,
            self.post_c_authorization_sha256,
        ):
            if type(value) is not str or HEX64.fullmatch(value) is None:
                raise RecoveredGateDPreflightError("gate_d_preflight_anchor_invalid")
        if (
            type(self.source_keys) is not tuple
            or len(self.source_keys) != 6
            or len(set(self.source_keys)) != 6
        ):
            raise RecoveredGateDPreflightError("gate_d_preflight_sources_invalid")
        if any(type(value) is not str or not value.strip() for value in self.source_keys):
            raise RecoveredGateDPreflightError("gate_d_preflight_sources_invalid")
        if not callable(self.clock):
            raise RecoveredGateDPreflightError("gate_d_preflight_clock_invalid")
        for value in (self.window_start_utc, self.expires_at_utc):
            if type(value) is not str or not value.endswith("Z"):
                raise RecoveredGateDPreflightError("gate_d_preflight_window_invalid")
        try:
            start = datetime.fromisoformat(self.window_start_utc[:-1] + "+00:00")
            end = datetime.fromisoformat(self.expires_at_utc[:-1] + "+00:00")
        except ValueError as exc:
            raise RecoveredGateDPreflightError("gate_d_preflight_window_invalid") from exc
        if start.tzinfo is not UTC or end.tzinfo is not UTC or not start < end:
            raise RecoveredGateDPreflightError("gate_d_preflight_window_invalid")
        if type(self.operation_id) is not str or not self.operation_id.strip():
            raise RecoveredGateDPreflightError("gate_d_preflight_operation_invalid")
        if (
            (self.historical_root, self.recovery_root, self.post_c_root)
            != (EXPECTED_HISTORICAL_ROOT, EXPECTED_RECOVERY_ROOT, EXPECTED_POST_C_ROOT)
            or self.operation_id != EXPECTED_OPERATION_ID
            or self.seal_sha256 != EXPECTED_SEAL_SHA256
            or self.source_plan_sha256 != EXPECTED_SOURCE_PLAN_SHA256
            or self.report_sha256 != EXPECTED_REPORT_SHA256
            or self.post_c_authorization_sha256 != EXPECTED_POST_C_AUTHORIZATION_SHA256
            or self.source_keys != EXPECTED_SOURCE_KEYS
        ):
            raise RecoveredGateDPreflightError("gate_d_preflight_trust_anchor_mismatch")

    def validate_current(self, now: datetime) -> None:
        if type(now) is not datetime or now.tzinfo is not UTC:
            raise RecoveredGateDPreflightError("gate_d_preflight_clock_invalid")
        start = datetime.fromisoformat(self.window_start_utc[:-1] + "+00:00")
        end = datetime.fromisoformat(self.expires_at_utc[:-1] + "+00:00")
        if not start <= now < end:
            raise RecoveredGateDPreflightError("gate_d_preflight_authorization_expired")


__all__ = [
    "ACTION",
    "EXPECTED_EVIDENCE_SHA256",
    "EXPECTED_EXPIRES_AT_UTC",
    "EXPECTED_HISTORICAL_APPROVAL",
    "EXPECTED_HISTORICAL_ROOT",
    "EXPECTED_OPERATION_ID",
    "EXPECTED_OPERATION_SHA256",
    "EXPECTED_PLAN_SHA256",
    "EXPECTED_POLICY_SHA256",
    "EXPECTED_POST_C_APPROVAL",
    "EXPECTED_POST_C_AUTHORIZATION_SHA256",
    "EXPECTED_POST_C_ROOT",
    "EXPECTED_PROFILE_ID",
    "EXPECTED_PROFILE_SHA256",
    "EXPECTED_PROFILE_VERSION",
    "EXPECTED_RECOVERY_ROOT",
    "EXPECTED_REPORT_SHA256",
    "EXPECTED_SEAL_SHA256",
    "EXPECTED_SOURCE_KEYS",
    "EXPECTED_SOURCE_PLAN_SHA256",
    "EXPECTED_STATE",
    "EXPECTED_TERMINAL_CODE",
    "EXPECTED_WINDOW_START_UTC",
    "RecoveredGateDPreflightAuthorization",
    "RecoveredGateDPreflightError",
]
