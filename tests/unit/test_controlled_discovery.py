from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from role_radar.collectors.registry import CollectorContext
from role_radar.discovery.contracts import (
    ProviderTier,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
)
from role_radar.evaluation.controlled_acquisition.acquisition import (
    EphemeralCollectorTaskFactory,
)
from role_radar.evaluation.controlled_acquisition.discovery import (
    DISCOVERY_CONFIRMATION,
    DISCOVERY_HOSTS,
    DiscoveryOrchestrator,
    DiscoveryQueryPlanner,
    VerifiedEphemeralConfig,
    require_discovery_confirmation,
)
from role_radar.evaluation.controlled_acquisition.protocols import (
    BASELINE_PROFILE_ID,
    BASELINE_PROFILE_SHA256,
    DISCOVERY_VERIFICATION_VERSION,
    PLAN_VERSION_V2,
    PROTOCOL_VERSION,
)
from role_radar.evaluation.controlled_acquisition.source_plan import (
    PlanError,
    load_plan,
    validate_live_plan_v2,
)
from role_radar.sources.identity import greenhouse_source_key

AS_OF = datetime(2026, 8, 12, 2, 0, tzinfo=UTC)
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_discovery_planner_is_bounded_and_uses_only_approved_hosts() -> None:
    queries = DiscoveryQueryPlanner().plan()
    assert len(queries) == 4
    assert tuple(query.canonical_query.split()[0][5:] for query in queries) == DISCOVERY_HOSTS
    assert all("Senior Frontend" in query.canonical_query for query in queries)
    assert all("609" not in query.canonical_query for query in queries)


def test_discovery_confirmation_is_exact() -> None:
    require_discovery_confirmation(DISCOVERY_CONFIRMATION)
    with pytest.raises(ValueError, match="discovery_confirmation_required"):
        require_discovery_confirmation("--yes")


class FakeProvider:
    provider = "brave"

    def __init__(self) -> None:
        self.requests: list[SearchRequest] = []

    async def search(self, request: SearchRequest) -> SearchResponse:
        self.requests.append(request)
        hits = (
            TransientSearchHit(url="https://boards.greenhouse.io/acme", rank=1),
            TransientSearchHit(url="https://example.invalid/not-ats", rank=2),
        )
        return SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="succeeded",
            hits=hits,
            result_count=len(hits),
        )

    async def aclose(self) -> None:
        return None


async def fake_verifier(candidate: Any, _as_of: datetime) -> VerifiedEphemeralConfig:
    return VerifiedEphemeralConfig(
        candidate=candidate,
        eligible_count=3,
        source_key=greenhouse_source_key(candidate.board_token),
        configuration={"board_token": candidate.board_token},
    )


@pytest.mark.asyncio
async def test_discovery_emits_plan_v2_without_source_rows() -> None:
    provider = FakeProvider()
    orchestrator = DiscoveryOrchestrator(query_hmac="query-secret", verifier=fake_verifier)
    report, plan = await orchestrator.run(
        brave=provider,
        tavily=provider,
        selection_as_of_utc=AS_OF,
        profile_sha256=BASELINE_PROFILE_SHA256,
        profile_id=BASELINE_PROFILE_ID,
        profile_version=2,
        profile_schema_version=1,
        source_commit="b" * 40,
        source_diff_sha256=EMPTY_SHA,
        source_status_sha256=EMPTY_SHA,
        alembic_head="e7a4c9f1b2d3",
    )
    assert len(provider.requests) == 8
    assert report.fallback_used is True
    assert plan.plan_version == PLAN_VERSION_V2
    assert plan.source_configs[0]["source_key"] == "greenhouse:acme"
    assert "source_id" not in plan.source_configs[0]
    loaded = load_plan(plan.as_dict())
    assert validate_live_plan_v2(loaded) == AS_OF
    assert loaded.protocol_version == PROTOCOL_VERSION
    assert loaded.verification_policy_version == DISCOVERY_VERIFICATION_VERSION


def test_plan_v1_is_rejected_for_live_use() -> None:
    with pytest.raises(PlanError, match="plan_version_unsupported"):
        validate_live_plan_v2(
            load_plan(
                {
                    "plan_version": "f10.1-plan-v1",
                    "lookback_days": 14,
                    "source_configs": [],
                    "wire_attempt_cap": 100,
                    "query_template_hashes": [],
                    "allowed_origins": [],
                    "profile_sha256": "a" * 64,
                    "profile_id": "profile",
                    "profile_version": 2,
                    "profile_schema_version": 1,
                    "selection_as_of_utc": None,
                    "jobicy_terms_sha256": None,
                    "jobicy_reviewed_at": None,
                    "jobicy_fair_use_ack": False,
                    "jobicy_destination_ack": False,
                    "jobicy_no_redistribution_ack": False,
                    "source_commit": None,
                    "source_diff_sha256": None,
                    "source_status_sha256": None,
                    "alembic_head": None,
                }
            )
        )


def test_ephemeral_factory_has_no_source_revision_dependency() -> None:
    plan = load_plan(
        {
            "plan_version": PLAN_VERSION_V2,
            "lookback_days": 14,
            "source_configs": [
                {
                    "family": "greenhouse",
                    "source_key": "greenhouse:acme",
                    "configuration_version": 1,
                    "configuration": {"board_token": "acme"},
                    "verification": {
                        "policy_version": DISCOVERY_VERIFICATION_VERSION,
                        "eligible_count": 1,
                    },
                }
            ],
            "wire_attempt_cap": 100,
            "query_template_hashes": ["a" * 64] * 4,
            "allowed_origins": [
                "https://api.eu.lever.co",
                "https://api.lever.co",
                "https://boards-api.greenhouse.io",
                "https://jobicy.com",
            ],
            "profile_sha256": "a" * 64,
            "profile_id": "profile",
            "profile_version": 2,
            "profile_schema_version": 1,
            "selection_as_of_utc": AS_OF.isoformat().replace("+00:00", "Z"),
            "jobicy_terms_sha256": None,
            "jobicy_reviewed_at": None,
            "jobicy_fair_use_ack": False,
            "jobicy_destination_ack": False,
            "jobicy_no_redistribution_ack": False,
            "source_commit": "b" * 40,
            "source_diff_sha256": EMPTY_SHA,
            "source_status_sha256": EMPTY_SHA,
            "alembic_head": "e7a4c9f1b2d3",
            "protocol_version": PROTOCOL_VERSION,
            "query_planner_version": "f10.1-discovery-queries-v1",
            "verification_policy_version": DISCOVERY_VERIFICATION_VERSION,
            "discovery_report_sha256": "c" * 64,
            "cutoff_utc": "2026-07-29T02:00:00Z",
        }
    )
    tasks = EphemeralCollectorTaskFactory(context=CollectorContext()).build(plan)
    assert len(tasks) == 1
    assert tasks[0].source_revision == 0
    assert tasks[0].snapshot.source_id.startswith("ephemeral:")
