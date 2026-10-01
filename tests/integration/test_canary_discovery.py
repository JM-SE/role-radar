from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository


def test_canary_discovery_searches_once_and_verifies_only_one_greenhouse(
    db_session,
) -> None:
    from datetime import UTC, datetime
    from types import MappingProxyType

    from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
    from role_radar.discovery.contracts import (
        DiscoveryPlan,
        PlannedQuery,
        ProviderIntent,
        ProviderTier,
        QueryIdentity,
        SearchResponse,
        TransientSearchHit,
    )
    from role_radar.domain.dto import RawJob
    from role_radar.domain.enums import DiscoveryMode
    from role_radar.repositories.discovery import DiscoveryRepository
    from role_radar.services.pipeline_discovery import PipelineDiscoveryService

    run = RunRepository(db_session).create_run("canary", discovery_mode=DiscoveryMode.SCHEDULED_DUE)
    run.canary_budget_json = dict(CANARY_BUDGET)
    cycle = DiscoveryRepository(db_session).create_cycle(
        run_id=run.id,
        profile_snapshot={},
        planner_version="planner-v1",
        planner_hash="hash",
        policy_version="policy-v1",
    )
    identity = QueryIdentity(1, "titles", ProviderIntent.EXACT, "query-key")
    DiscoveryRepository(db_session).add_query(cycle_id=cycle.id, identity=identity)
    db_session.commit()
    run_id, cycle_id = run.id, cycle.id

    class Provider:
        calls = 0

        async def search_canary(self, _request):
            self.calls += 1
            return SearchResponse(
                provider="brave",
                tier=ProviderTier.FREE,
                status="succeeded",
                result_count=3,
                hits=(
                    TransientSearchHit(url="https://boards.greenhouse.io/acme/jobs/1", rank=1),
                    TransientSearchHit(url="https://boards.greenhouse.io/other/jobs/2", rank=2),
                    TransientSearchHit(url="https://jobs.lever.co/acme/3", rank=3),
                ),
            )

    class Collector:
        async def collect(self, _snapshot, _runtime):
            job = RawJob(
                source="greenhouse",
                external_id="1",
                title="Senior Frontend Engineer",
                company="Acme",
                location="Remote",
                source_url="https://boards.greenhouse.io/acme/jobs/1",
                application_url="https://boards.greenhouse.io/acme/jobs/1",
                description="Fully remote position. Work remotely from Argentina.",
                structured_data={"id": "1"},
                collected_at=datetime.now(UTC),
            )
            return CollectionSuccess(
                status="ok",
                jobs=(job,),
                metrics=CollectionMetrics(provider_items=1, accepted_items=1),
            )

    provider = Provider()
    verified_collectors = []

    def collector_factory(snapshot):
        verified_collectors.append(snapshot.source_type)
        return Collector()

    service = PipelineDiscoveryService(
        lambda: db_session,
        provider=provider,
        collector_factory=collector_factory,
    )
    plan = DiscoveryPlan(
        run_id=run_id,
        cycle_id=cycle_id,
        profile_snapshot=MappingProxyType({}),
        queries=(PlannedQuery(1, "titles", ProviderIntent.EXACT, "profile query"),),
        identities=(identity,),
        planner_version="planner-v1",
        planner_hash="hash",
        policy_version="policy-v1",
    )

    execution = __import__("asyncio").run(service.execute(plan))

    assert provider.calls == 1
    assert len(verified_collectors) == 1
    assert verified_collectors[0] == "greenhouse"
    assert len(execution.verified_batches) == 1
