"""Recovered-only Gate D adaptation boundary.

This module deliberately exposes only a synthetic callback seam. It never
constructs ordinary Gate D requests and never imports the Gate D runtime.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from .recovered_gate_d_adaptation import (
    RecoveredGateDAdaptationBinding,
    _issue_binding,
)
from .recovered_gate_d_adaptation_authorization import (
    RecoveredGateDAdaptationAuthorization,
    RecoveredGateDAdaptationAuthorizationError,
)
from .recovered_gate_d_authorization import RecoveredGateDPreflightAuthorization
from .recovered_gate_d_loader import load_recovered_gate_d_preflight


class RecoveredGateDAdaptationServiceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _preflight_authorization(
    authorization: RecoveredGateDAdaptationAuthorization,
) -> RecoveredGateDPreflightAuthorization:
    return RecoveredGateDPreflightAuthorization(
        action="offline_compatibility_preflight",
        approval_reference=authorization.approval_reference,
        operator_id=authorization.operator_id,
        window_start_utc=authorization.window_start_utc,
        expires_at_utc=authorization.expires_at_utc,
        historical_root=authorization.historical_root,
        recovery_root=authorization.recovery_root,
        post_c_root=authorization.post_c_root,
        operation_id=authorization.operation_id,
        seal_sha256=authorization.seal_sha256,
        source_plan_sha256=authorization.source_plan_sha256,
        report_sha256=authorization.report_sha256,
        post_c_authorization_sha256=authorization.post_c_authorization_sha256,
        source_keys=authorization.source_keys,
        clock=authorization.clock,
    )


def authorize_recovered_gate_d(
    authorization: RecoveredGateDAdaptationAuthorization,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RecoveredGateDAdaptationBinding:
    """Revalidate the complete preflight and issue a recovered-only binding."""
    if type(authorization) is not RecoveredGateDAdaptationAuthorization:
        raise RecoveredGateDAdaptationServiceError("recovered_gate_d_authorization_invalid")
    trusted_clock = authorization.clock if clock is None else clock
    try:
        if not callable(trusted_clock):
            raise RecoveredGateDAdaptationServiceError("recovered_gate_d_clock_invalid")
        authorization.validate_current(trusted_clock())
        state, terminal, count = load_recovered_gate_d_preflight(
            _preflight_authorization(authorization), clock=trusted_clock
        )
        authorization.validate_current(trusted_clock())
        return _issue_binding(authorization, state, terminal, count)
    except RecoveredGateDAdaptationServiceError:
        raise
    except (RecoveredGateDAdaptationAuthorizationError, ValueError) as exc:
        raise RecoveredGateDAdaptationServiceError(
            getattr(exc, "code", "recovered_gate_d_preflight_invalid")
        ) from exc


def run_recovered_gate_d_synthetic(
    authorization: RecoveredGateDAdaptationAuthorization,
    delegate: Callable[[RecoveredGateDAdaptationBinding], object],
    *,
    clock: Callable[[], datetime] | None = None,
) -> object:
    """Exercise only an injected synthetic seam after final authorization."""
    if not callable(delegate):
        raise RecoveredGateDAdaptationServiceError("recovered_gate_d_synthetic_delegate_required")
    binding = authorize_recovered_gate_d(authorization, clock=clock)
    final_clock = authorization.clock if clock is None else clock
    authorization.validate_current(final_clock())
    return delegate(binding)


__all__ = [
    "RecoveredGateDAdaptationServiceError",
    "authorize_recovered_gate_d",
    "run_recovered_gate_d_synthetic",
]
