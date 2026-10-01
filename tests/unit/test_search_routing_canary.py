from types import SimpleNamespace

import pytest

from role_radar.discovery.contracts import (
    ProviderIntent,
    ProviderTier,
    SearchRequest,
    SearchResponse,
)
from role_radar.discovery.routing import ProviderName
from role_radar.services.search_routing_service import SearchRoutingService


@pytest.mark.asyncio
async def test_canary_search_is_brave_free_only() -> None:
    service = SearchRoutingService.__new__(SearchRoutingService)
    service._brave = object()
    service._tavily = object()
    service._config = SimpleNamespace(brave_free=SimpleNamespace(enabled=True))
    calls = []

    async def run_one(request, provider, tier, reason, *, skip_memo=False):
        calls.append((provider, tier, reason, skip_memo))
        return SearchResponse(provider="brave", tier=tier, status="empty")

    service._run_one = run_one
    request = SearchRequest(
        operation_key="cycle:query:1",
        query="profile-derived role query",
        query_key="query-key",
        planner_version="planner-v1",
        query_version="policy-v1",
        provider_intent=ProviderIntent.EXACT,
    )

    await service.search_canary(request)

    assert calls == [(ProviderName.BRAVE, ProviderTier.FREE, "canary_brave_only", True)]


@pytest.mark.asyncio
async def test_canary_search_does_not_fallback_when_brave_is_unavailable() -> None:
    service = SearchRoutingService.__new__(SearchRoutingService)
    service._brave = None
    service._tavily = object()
    service._config = SimpleNamespace(brave_free=SimpleNamespace(enabled=True))
    request = SearchRequest(
        operation_key="cycle:query:1",
        query="profile-derived role query",
        query_key="query-key",
        planner_version="planner-v1",
        query_version="policy-v1",
        provider_intent=ProviderIntent.EXACT,
    )

    response = await service.search_canary(request)

    assert response.provider == "brave"
    assert response.error_code == "provider_unavailable"
