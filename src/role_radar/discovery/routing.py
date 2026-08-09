"""Pure deterministic free-first search routing policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from role_radar.discovery.contracts import ProviderIntent, ProviderTier


class ProviderName(StrEnum):
    BRAVE = "brave"
    TAVILY = "tavily"


@dataclass(frozen=True, slots=True)
class RouteDecision:
    provider: ProviderName | None
    tier: ProviderTier | None
    reason: str


@dataclass(frozen=True, slots=True)
class RoutingAvailability:
    total_queries: int
    semantic_queries_used: int = 0
    query_calls_used: int = 0
    cycle_calls_used: int = 0
    brave_free_available: bool = False
    tavily_free_available: bool = False
    brave_paid_available: bool = False


@dataclass(frozen=True, slots=True)
class RoutingOutcome:
    provider: ProviderName
    tier: ProviderTier
    status: str
    unique_allowlisted_candidates: int = 0


def semantic_limit(total_queries: int) -> int:
    return min(total_queries // 5, max(0, total_queries // 5))


def choose_route(
    *,
    intent: ProviderIntent,
    availability: RoutingAvailability,
    outcomes: tuple[RoutingOutcome, ...] = (),
    memo_reusable: bool = False,
) -> RouteDecision:
    if memo_reusable:
        return RouteDecision(None, None, "memo")
    if availability.query_calls_used >= 2 or availability.cycle_calls_used >= 48:
        return RouteDecision(None, None, "call_cap")
    if intent is ProviderIntent.SEMANTIC:
        if availability.semantic_queries_used >= semantic_limit(availability.total_queries):
            return RouteDecision(None, None, "semantic_cap")
        if availability.tavily_free_available:
            return RouteDecision(ProviderName.TAVILY, ProviderTier.FREE, "semantic_primary")
        return RouteDecision(None, None, "semantic_free_unavailable")

    brave_succeeded = any(
        item.provider is ProviderName.BRAVE
        and item.tier is ProviderTier.FREE
        and item.status == "succeeded"
        for item in outcomes
    )
    if brave_succeeded:
        low_yield = outcomes[-1].unique_allowlisted_candidates < 3 if outcomes else False
        if low_yield and availability.tavily_free_available:
            return RouteDecision(ProviderName.TAVILY, ProviderTier.FREE, "low_yield_complement")
        return RouteDecision(None, None, "exact_complete")
    if not outcomes and availability.brave_free_available:
        return RouteDecision(ProviderName.BRAVE, ProviderTier.FREE, "exact_primary")
    if not outcomes and availability.tavily_free_available:
        return RouteDecision(ProviderName.TAVILY, ProviderTier.FREE, "brave_overflow")
    free_exhausted = (
        not availability.brave_free_available and not availability.tavily_free_available
    )
    if free_exhausted and availability.brave_paid_available and not outcomes:
        return RouteDecision(ProviderName.BRAVE, ProviderTier.PAID, "paid_after_free_exhaustion")
    return RouteDecision(None, None, "free_unavailable")
