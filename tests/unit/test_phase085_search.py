"""Offline contracts for F8.5 search, routing and paid budget gates."""

import json
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from role_radar.discovery.acquisition_config import (
    AcquisitionConfig,
    BravePaidConfig,
    FreeQuota,
)
from role_radar.discovery.contracts import ProviderIntent, SearchRequest
from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider
from role_radar.discovery.routing import RoutingAvailability, choose_route
from role_radar.services.acquisition_budget_service import (
    AcquisitionBudgetService,
    AcquisitionOperation,
)


def _request() -> SearchRequest:
    return SearchRequest(
        operation_key="cycle:query:0",
        query="site:boards.greenhouse.io backend engineer",
        query_key="hmac-only",
        planner_version="planner-v1",
        query_version="policy-v1",
        provider_intent=ProviderIntent.EXACT,
    )


def test_request_hides_transient_query_and_rejects_obvious_pii() -> None:
    request = _request()
    assert request.query not in repr(request)
    with pytest.raises(ValueError):
        SearchRequest(
            operation_key="operation",
            query="candidate@example.com backend",
            query_key="hmac",
            planner_version="planner-v1",
            query_version="policy-v1",
            provider_intent=ProviderIntent.EXACT,
        )


@pytest.mark.asyncio
async def test_search_adapters_are_fixed_and_minimized() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload: dict[str, object]
        if request.method == "GET":
            payload = {
                "web": {
                    "results": [
                        {
                            "title": "must not escape",
                            "url": "https://boards.greenhouse.io/acme/jobs/1",
                            "description": "must not escape",
                        }
                    ]
                }
            }
        else:
            payload = {
                "answer": "must not escape",
                "results": [
                    {
                        "title": "must not escape",
                        "url": "https://jobs.lever.co/acme/job-1",
                        "content": "must not escape",
                    }
                ],
            }
        return httpx.Response(
            200, headers={"content-type": "application/json"}, content=json.dumps(payload)
        )

    transport = httpx.MockTransport(handler)
    async with BraveSearchProvider("brave-secret", transport=transport) as brave:
        brave_result = await brave.search(_request())
    async with TavilySearchProvider("tavily-secret", transport=transport) as tavily:
        tavily_result = await tavily.search(_request())

    assert brave_result.hits[0].url.endswith("/1")
    assert tavily_result.hits[0].url.endswith("job-1")
    assert "title" not in repr(brave_result)
    assert seen[0].method == "GET" and seen[0].url.path == "/res/v1/web/search"
    assert seen[1].method == "POST" and seen[1].url.path == "/search"
    tavily_body = json.loads(seen[1].content)
    assert tavily_body["include_answer"] is False
    assert tavily_body["include_raw_content"] is False


def test_routing_enforces_free_first_and_two_call_cap() -> None:
    decision = choose_route(
        intent=ProviderIntent.EXACT,
        availability=RoutingAvailability(
            total_queries=10,
            brave_free_available=True,
            tavily_free_available=True,
            brave_paid_available=True,
        ),
    )
    assert decision.reason == "exact_primary"
    decision = choose_route(
        intent=ProviderIntent.EXACT,
        availability=RoutingAvailability(
            total_queries=10,
            query_calls_used=2,
            brave_paid_available=True,
        ),
    )
    assert decision.provider is None


def test_brave_paid_cap_allows_exact_limit_and_rejects_one_micro_usd_over(
    db_engine: Engine,
) -> None:
    config = AcquisitionConfig(
        config_version="test-v1",
        brave_free=FreeQuota(),
        tavily_free=FreeQuota(),
        brave_paid=BravePaidConfig(
            enabled=True,
            quote_version="quote-v1",
            reviewed_at=datetime.now(UTC),
            unit_price_micro_usd=5_000_000,
            provider_ceiling_micro_usd=5_000_000,
            provider_ceiling_evidence=True,
            payment_control_evidence=True,
        ),
    )
    service = AcquisitionBudgetService(lambda: Session(db_engine), config)
    operation = AcquisitionOperation("paid-exact", "brave", "paid", "cycle", "h", 0, 5_000_000)
    assert service.reserve(operation) is not None
    assert service.reserve(
        AcquisitionOperation("paid-over", "brave", "paid", "cycle", "h", 1, 1)
    ) is None
