"""Free-only routing pins: Brave terminal states never call Tavily.

Uses the existing v2 bounded runtime with fake providers, fake quota, and a
sealed test capability. No network, no credentials.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Literal, cast

from role_radar.continuous_acquisition.discovery_budget_v2 import DiscoveryBudgetV2
from role_radar.continuous_acquisition.providers import (
    BoundedSearchRuntime,
    SearchAuthorizationCapability,
)
from role_radar.continuous_acquisition.runtime_discovery_v2 import build_search_runtime
from role_radar.discovery.contracts import ProviderTier, SearchResponse, TransientSearchHit
from role_radar.discovery.planner_v2 import plan_profile_discovery
from role_radar.discovery.policy import (
    DiscoveryPhraseGrammarV1,
    DiscoveryPolicyV1,
    policy_sha256,
)
from role_radar.discovery.profile_terms import (
    CompiledDiscoveryPhraseV1,
    CompiledDiscoveryTermsV1,
    DiscoveryTermProvenanceV1,
)

NOW = datetime(2026, 9, 10, 1, tzinfo=UTC)


def _plan() -> Any:
    policy = DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": "1",
            "profile_binding": {
                "profile_id": "00000000-0000-0000-0000-000000000001",
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": "c" * 64,
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {"primary": ["Backend Engineer"]},
            "target_roles": {"backend": {"primary_groups": ["primary"]}},
            "target_titles": {},
        }
    )
    terms = CompiledDiscoveryTermsV1(
        profile_binding=policy.profile_binding,
        policy_version=policy.policy_version,
        policy_sha256=policy_sha256(policy),
        phrases=(
            CompiledDiscoveryPhraseV1(
                "Backend Engineer",
                (DiscoveryTermProvenanceV1("target_roles", "backend", "primary", False),),
            ),
        ),
    )
    return plan_profile_discovery(terms, policy)


class _Config:
    config_version = "config-v1"

    class brave_free:
        enabled = True
        units_limit = 4

    class tavily_free:
        enabled = True
        units_limit = 4


class _Publication:
    reservation_id = "reservation-1"


class _QuotaAdapter:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.commits = 0

    def reserve_and_start_v2(self, *, operation_key: str, **_kwargs: object) -> _Publication:
        self.started.append(operation_key)
        return _Publication()

    def finalize_v2(self, *, reservation_id: str, **_kwargs: object) -> object:
        return object()

    def revalidate_context_v2(self, *, context: object, **_kwargs: object) -> object:
        return context

    def commit_v2(self) -> None:
        self.commits += 1


def _capability(plan: Any) -> SearchAuthorizationCapability:
    capability = object.__new__(SearchAuthorizationCapability)
    object.__setattr__(capability, "operation_id", "11111111-1111-4111-8111-111111111111")
    object.__setattr__(capability, "operation_sha256", "0" * 64)
    object.__setattr__(capability, "plan_sha256", plan.plan_sha256)
    object.__setattr__(capability, "expires_at_utc", datetime(2026, 9, 11, tzinfo=UTC))
    object.__setattr__(capability, "allowed_providers", ("brave", "tavily"))
    object.__setattr__(capability, "authorization_sha256", None)
    return capability


class _StubProvider:
    def __init__(
        self, provider: Literal["brave", "tavily"], status: str, urls: tuple[str, ...] = ()
    ) -> None:
        self.provider = provider
        self.status = status
        self.urls = urls
        self.calls = 0

    async def search(self, _request: object) -> SearchResponse:
        self.calls += 1
        hits = tuple(
            TransientSearchHit(url=url, rank=index + 1) for index, url in enumerate(self.urls)
        )
        return SearchResponse(
            provider=cast(Any, self.provider),
            tier=ProviderTier.FREE,
            status=cast(Any, self.status),
            hits=hits,
            result_count=len(hits),
            known_count=len(hits),
        )


class _ExplodingProvider:
    provider = "brave"

    async def search(self, _request: object) -> SearchResponse:
        raise OSError("transport unavailable")


def _runtime(plan: Any, brave: Any, tavily: Any) -> tuple[BoundedSearchRuntime, _QuotaAdapter]:
    quota = _QuotaAdapter()
    runtime = build_search_runtime(
        _Config(),
        plan,
        authorization_capability=_capability(plan),
        execution_budget=DiscoveryBudgetV2(),
        quota_adapter=quota,  # type: ignore[arg-type]
    )
    runtime.brave = brave
    runtime.tavily = tavily
    runtime.before_transport_check = None
    runtime.clock = lambda: NOW
    return runtime, quota


def test_brave_succeeded_never_calls_tavily() -> None:
    plan = _plan()
    brave = _StubProvider("brave", "succeeded", ("https://boards.greenhouse.io/acme",))
    tavily = _StubProvider("tavily", "succeeded", ("https://jobs.lever.co/acme",))
    runtime, _ = _runtime(plan, brave, tavily)
    candidates = asyncio.run(runtime.search())
    assert brave.calls == 4
    assert tavily.calls == 0
    assert {candidate.source_type for candidate in candidates} == {"greenhouse"}


def test_brave_empty_never_calls_tavily() -> None:
    plan = _plan()
    brave = _StubProvider("brave", "empty")
    tavily = _StubProvider("tavily", "succeeded", ("https://jobs.lever.co/acme",))
    runtime, _ = _runtime(plan, brave, tavily)
    candidates = asyncio.run(runtime.search())
    assert brave.calls == 4
    assert tavily.calls == 0
    assert candidates == ()


def test_brave_failed_falls_back_to_tavily_free_once_per_query() -> None:
    plan = _plan()
    brave = _StubProvider("brave", "failed")
    tavily = _StubProvider("tavily", "succeeded", ("https://jobs.lever.co/acme",))
    runtime, _ = _runtime(plan, brave, tavily)
    candidates = asyncio.run(runtime.search())
    assert brave.calls == 4
    assert tavily.calls == 4
    assert {candidate.source_type for candidate in candidates} == {"lever"}


def test_brave_malformed_falls_back_to_tavily() -> None:
    plan = _plan()
    brave = _StubProvider("brave", "malformed")
    tavily = _StubProvider("tavily", "empty")
    runtime, _ = _runtime(plan, brave, tavily)
    asyncio.run(runtime.search())
    assert brave.calls == 4
    assert tavily.calls == 4


def test_indeterminate_never_falls_through() -> None:
    plan = _plan()
    brave = _ExplodingProvider()
    tavily = _StubProvider("tavily", "succeeded", ("https://jobs.lever.co/acme",))
    runtime, _ = _runtime(plan, brave, tavily)
    try:
        asyncio.run(runtime.search())
    except RuntimeError as exc:
        assert "transmission_indeterminate" in str(exc)
    else:
        raise AssertionError("indeterminate transmission must stop")
    assert tavily.calls == 0


def test_fixed_budgets_hold() -> None:
    plan = _plan()
    assert plan.max_brave_requests_per_run == 4
    assert plan.max_tavily_requests_per_run == 4
    assert plan.max_unique_board_candidates_per_run == 10
    assert plan.max_unique_board_verifications_per_run == 8
    assert plan.max_verification_wire_attempts_per_run == 100
