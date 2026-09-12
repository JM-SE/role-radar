"""Typed, recovered-only Gate D predecessor binding."""

from __future__ import annotations

from dataclasses import dataclass, field

from .recovered_gate_d_adaptation_authorization import (
    RecoveredGateDAdaptationAuthorization,
)

_BINDING_TOKEN = object()


@dataclass(frozen=True, slots=True)
class RecoveredGateDAdaptationBinding:
    authorization: RecoveredGateDAdaptationAuthorization
    predecessor_state: str
    predecessor_terminal: str
    source_count: int
    _token: object = field(default=None, repr=False, compare=False, kw_only=True)

    def __post_init__(self) -> None:
        if self._token is not _BINDING_TOKEN:
            raise ValueError("recovered_gate_d_binding_not_loader_issued")
        if (
            self.predecessor_state != "completed_partial"
            or self.predecessor_terminal != "multiple_budgets_exhausted"
            or self.source_count != 6
        ):
            raise ValueError("recovered_gate_d_predecessor_invalid")


def _issue_binding(
    authorization: RecoveredGateDAdaptationAuthorization,
    predecessor_state: str,
    predecessor_terminal: str,
    source_count: int,
) -> RecoveredGateDAdaptationBinding:
    return RecoveredGateDAdaptationBinding(
        authorization,
        predecessor_state,
        predecessor_terminal,
        source_count,
        _token=_BINDING_TOKEN,
    )


__all__ = ["RecoveredGateDAdaptationBinding"]
