"""Bounded, report-only smoke orchestration for the remaining Gate B sources."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from role_radar.collectors.outcomes import CollectionFailure, CollectionSuccess
from role_radar.discovery.contracts import SearchRequest, SearchResponse

GateState = Literal["ok", "failed"]
SmokeOperation = Callable[[], Awaitable["GateBSmokeResult"]]


@dataclass(frozen=True, slots=True)
class GateBSmokeResult:
    capability: str
    state: GateState
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


@dataclass(frozen=True, slots=True)
class GateBSmokeReport:
    state: GateState
    results: tuple[GateBSmokeResult, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "acquisition-gate-b-v1",
            "state": self.state,
            "results": [item.as_dict() for item in self.results],
        }


class AcquisitionGateBSmokeService:
    """Run injected adapters sequentially without persistence or source mutation."""

    async def run_sequence(
        self, operations: Sequence[tuple[str, SmokeOperation]]
    ) -> GateBSmokeReport:
        results: list[GateBSmokeResult] = []
        for capability, operation in operations:
            try:
                result = await operation()
            except Exception:
                result = GateBSmokeResult(capability, "failed", "smoke_failed", 1)
            if result.capability != capability:
                result = GateBSmokeResult(capability, "failed", "invalid_outcome", 1)
            results.append(result)
            if result.state != "ok":
                return GateBSmokeReport("failed", tuple(results))
        return GateBSmokeReport("ok", tuple(results))

    @staticmethod
    async def run_jobicy(collector: Any) -> GateBSmokeResult:
        from role_radar.collectors.policy import CollectionRunBudget
        from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot

        snapshot = SourceSnapshot(
            source_id="gate-b-smoke:jobicy",
            source_type="jobicy",
            name="Gate B Jobicy smoke",
            configuration={"region": "latam", "remote_only": True},
            source_key="jobicy:latam",
            configuration_version=1,
        )
        outcome = await collector.collect(
            snapshot,
            CollectorRuntime(budget=CollectionRunBudget(1)),
        )
        if isinstance(outcome, CollectionFailure):
            if outcome.metrics.logical_requests > 1 or outcome.metrics.wire_attempts > 1:
                return GateBSmokeResult("jobicy", "failed", "request_limit", 1)
            return GateBSmokeResult(
                "jobicy",
                "failed",
                outcome.error_code.value,
                outcome.metrics.logical_requests,
            )
        if not isinstance(outcome, CollectionSuccess):
            return GateBSmokeResult("jobicy", "failed", "invalid_outcome", 1)
        if outcome.metrics.logical_requests != 1 or outcome.metrics.wire_attempts > 1:
            return GateBSmokeResult("jobicy", "failed", "request_limit", 1)
        return GateBSmokeResult("jobicy", "ok", None, 1, len(outcome.jobs))

    @staticmethod
    async def run_search(
        capability: str, provider: Any, request: SearchRequest
    ) -> GateBSmokeResult:
        response = await provider.search(request)
        if not isinstance(response, SearchResponse):
            return GateBSmokeResult(capability, "failed", "invalid_outcome", 1)
        if response.provider != capability or response.tier.value != "free":
            return GateBSmokeResult(capability, "failed", "provider_policy", 1)
        if response.result_count > 1 or len(response.hits) > 1:
            return GateBSmokeResult(capability, "failed", "result_limit", 1)
        if response.status in {"succeeded", "empty"}:
            return GateBSmokeResult(capability, "ok", None, 1, response.result_count)
        return GateBSmokeResult(
            capability,
            "failed",
            response.error_code or response.status,
            1,
        )
