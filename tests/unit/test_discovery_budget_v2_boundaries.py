"""Offline boundary checks for the immutable discovery-v2 budgets."""

import pytest

from role_radar.continuous_acquisition.discovery_budget_v2 import (
    DiscoveryBudgetError,
    DiscoveryBudgetV2,
)


@pytest.mark.parametrize(
    ("reserve", "limit", "provider", "expected_code"),
    (
        ("reserve_search", 4, "brave", "discovery_budget_exhausted"),
        ("reserve_search", 4, "tavily", "discovery_budget_exhausted"),
        ("reserve_candidate", 10, None, "discovery_candidate_cap_exhausted"),
        ("reserve_verification", 8, None, "discovery_verification_cap_exhausted"),
        ("reserve_wire_attempt", 100, None, "discovery_wire_cap_exhausted"),
    ),
)
def test_discovery_budget_rejects_first_operation_over_limit(
    reserve: str,
    limit: int,
    provider: str | None,
    expected_code: str,
) -> None:
    budget = DiscoveryBudgetV2()
    reserve_operation = getattr(budget, reserve)
    for _ in range(limit):
        reserve_operation(provider) if provider is not None else reserve_operation()

    with pytest.raises(DiscoveryBudgetError) as exc_info:
        reserve_operation(provider) if provider is not None else reserve_operation()

    assert exc_info.value.code == expected_code
