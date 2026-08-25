"""Bounded, report-only Gate B smoke tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from role_radar.cli.main import main
from role_radar.collectors.outcomes import (
    CollectionFailure,
    CollectionMetrics,
    CollectionSuccess,
    CollectorFailureCode,
)
from role_radar.discovery.contracts import ProviderTier, SearchResponse, TransientSearchHit
from role_radar.services.acquisition_gate_b_smoke import (
    AcquisitionGateBSmokeService,
    GateBSmokeResult,
)


class FakeJobicyCollector:
    async def collect(self, _snapshot: object, _runtime: object) -> CollectionSuccess:
        return CollectionSuccess(
            status="ok",
            jobs=(),
            metrics=CollectionMetrics(
                logical_requests=1,
                wire_attempts=1,
            ),
        )


class FakeSearchProvider:
    def __init__(self, response: SearchResponse) -> None:
        self.response = response

    async def search(self, _request: object) -> SearchResponse:
        return self.response


@pytest.mark.asyncio
async def test_gate_b_runs_jobicy_brave_and_tavily_in_order() -> None:
    calls: list[str] = []
    service = AcquisitionGateBSmokeService()

    async def step(name: str) -> GateBSmokeResult:
        calls.append(name)
        return GateBSmokeResult(name, "ok", None, 1, 1)

    def operation(name: str) -> Callable[[], Awaitable[GateBSmokeResult]]:
        async def run() -> GateBSmokeResult:
            return await step(name)

        return run

    report = await service.run_sequence(
        tuple((name, operation(name)) for name in ("jobicy", "brave", "tavily"))
    )

    assert report.state == "ok"
    assert calls == ["jobicy", "brave", "tavily"]
    assert [item.logical_requests for item in report.results] == [1, 1, 1]


@pytest.mark.asyncio
async def test_gate_b_stops_before_next_capability_on_failure() -> None:
    calls: list[str] = []
    service = AcquisitionGateBSmokeService()

    async def failing() -> GateBSmokeResult:
        calls.append("jobicy")
        return GateBSmokeResult("jobicy", "failed", "upstream", 1)

    async def should_not_run() -> GateBSmokeResult:
        calls.append("brave")
        return GateBSmokeResult("brave", "ok", None, 1, 1)

    report = await service.run_sequence((("jobicy", failing), ("brave", should_not_run)))

    assert report.state == "failed"
    assert calls == ["jobicy"]
    assert len(report.results) == 1


@pytest.mark.asyncio
async def test_gate_b_jobicy_smoke_is_one_request_and_report_only() -> None:
    result = await AcquisitionGateBSmokeService.run_jobicy(FakeJobicyCollector())

    assert result.as_dict() == {
        "capability": "jobicy",
        "state": "ok",
        "code": None,
        "logical_requests": 1,
        "output_count": 0,
    }


@pytest.mark.asyncio
async def test_gate_b_rejects_jobicy_retry_or_wire_overrun() -> None:
    class RetryingCollector:
        async def collect(self, _snapshot: object, _runtime: object) -> CollectionFailure:
            return CollectionFailure(
                status="failed",
                error_code=CollectorFailureCode.UPSTREAM,
                metrics=CollectionMetrics(logical_requests=1, wire_attempts=2),
            )

    result = await AcquisitionGateBSmokeService.run_jobicy(RetryingCollector())

    assert result.code == "request_limit"
    assert result.state == "failed"


@pytest.mark.asyncio
async def test_gate_b_search_accepts_empty_free_response() -> None:
    provider = FakeSearchProvider(
        SearchResponse(provider="brave", tier=ProviderTier.FREE, status="empty")
    )

    result = await AcquisitionGateBSmokeService.run_search(
        "brave",
        provider,
        object(),  # type: ignore[arg-type]
    )

    assert result.state == "ok"
    assert result.output_count == 0


@pytest.mark.asyncio
async def test_gate_b_rejects_search_result_overrun() -> None:
    provider = FakeSearchProvider(
        SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="succeeded",
            hits=(
                TransientSearchHit(url="https://example.test/1", rank=1),
                TransientSearchHit(url="https://example.test/2", rank=2),
            ),
            result_count=2,
        )
    )

    result = await AcquisitionGateBSmokeService.run_search(
        "brave",
        provider,
        object(),  # type: ignore[arg-type]
    )

    assert result.as_dict() == {
        "capability": "brave",
        "state": "failed",
        "code": "result_limit",
        "logical_requests": 1,
        "output_count": 0,
    }


def test_gate_b_requires_explicit_ack_without_opening_live_adapters() -> None:
    assert main(["acquisition", "gate-b"]) == 4
