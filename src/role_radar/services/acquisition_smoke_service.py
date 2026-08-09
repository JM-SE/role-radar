"""Opt-in smoke orchestration with hard one-operation limits."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any

from role_radar.acquisition.activation import ActivationError, require_live_smoke_ack


@dataclass(frozen=True, slots=True)
class SmokeResult:
    capability: str
    state: str
    code: str | None
    logical_requests: int
    output_count: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability,
            "state": self.state,
            "code": self.code,
            "logical_requests": self.logical_requests,
            "output_count": self.output_count,
        }


class AcquisitionSmokeService:
    """Adapters are injected, making accidental live I/O impossible in Gate A."""

    async def run(
        self,
        capability: str,
        *,
        ack_live: bool = False,
        confirmation: str | None = None,
        adapter: Any = None,
    ) -> SmokeResult:
        try:
            require_live_smoke_ack(
                ack_live=ack_live,
                confirmation=confirmation,
                capability=capability,
            )
        except ActivationError as exc:
            return SmokeResult(capability, "blocked", exc.code, 0)
        if adapter is None:
            return SmokeResult(capability, "blocked", "adapter_unavailable", 0)
        try:
            value = adapter()
            if inspect.isawaitable(value):
                value = await value
            count = len(value) if hasattr(value, "__len__") else 1
            return SmokeResult(capability, "ok", None, 1, min(count, 1))
        except Exception:
            return SmokeResult(capability, "failed", "smoke_failed", 1)
