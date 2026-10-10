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
    assert execution.board_verification_counts == (0, 0, 0)


def test_board_verification_diagnostics_are_local_and_preserve_accepted_jobs(
    db_session, monkeypatch
) -> None:
    from datetime import UTC, datetime

    from role_radar.collectors.outcomes import (
        CollectionFailure,
        CollectionMetrics,
        CollectionSuccess,
        CollectorFailureCode,
    )
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
    from role_radar.domain.enums import DiscoveryCycleStatus, DiscoveryMode
    from role_radar.repositories.discovery import DiscoveryRepository
    from role_radar.services.acquired_job_writer import AcquiredJobWriter, AcquiredWriteResult
    from role_radar.services.pipeline_discovery import PipelineDiscoveryService

    monkeypatch.setattr(
        AcquiredJobWriter,
        "write",
        lambda *_args, **_kwargs: AcquiredWriteResult(0, 0, 0, 0, 0, 0, (), ()),
    )
    invalid_job = RawJob(
        source="greenhouse",
        external_id="invalid",
        title="",
        company="Synthetic",
        description="",
        source_url="https://boards.greenhouse.io/synthetic/jobs/invalid",
        collected_at=datetime.now(UTC),
    )
    accepted_jobs = (
        RawJob(
            source="greenhouse",
            external_id="accepted",
            title="Backend Engineer",
            company="Synthetic",
            description="Synthetic role description",
            source_url="https://boards.greenhouse.io/synthetic/jobs/accepted",
            application_url="https://boards.greenhouse.io/synthetic/jobs/accepted",
            collected_at=datetime.now(UTC),
        ),
    )
    outcomes = iter(
        (
            CollectionFailure("failed", CollectorFailureCode.INTERNAL, CollectionMetrics()),
            CollectionSuccess("ok", (), CollectionMetrics()),
            CollectionSuccess(
                "ok", (invalid_job,), CollectionMetrics(provider_items=1, accepted_items=1)
            ),
            CollectionSuccess(
                "ok", accepted_jobs, CollectionMetrics(provider_items=1, accepted_items=1)
            ),
        )
    )

    class Provider:
        async def search(self, _request):
            return SearchResponse(
                provider="brave",
                tier=ProviderTier.FREE,
                status="succeeded",
                hits=(
                    TransientSearchHit(
                        url="https://boards.greenhouse.io/synthetic/jobs/1", rank=1
                    ),
                ),
            )

    class Collector:
        async def collect(self, _snapshot, _runtime):
            return next(outcomes)

    service = PipelineDiscoveryService(
        lambda: db_session,
        provider=Provider(),
        collector_factory=lambda _snapshot: Collector(),
    )
    executions = []
    cycles = []
    for index in range(4):
        run = RunRepository(db_session).create_run(
            "synthetic", discovery_mode=DiscoveryMode.SCHEDULED_DUE
        )
        cycle = DiscoveryRepository(db_session).create_cycle(
            run_id=run.id,
            profile_snapshot={},
            planner_version="test",
            planner_hash="test",
            policy_version="test",
        )
        db_session.commit()
        identity = QueryIdentity(index + 1, "synthetic", ProviderIntent.EXACT, f"key-{index}")
        plan = DiscoveryPlan(
            run.id,
            cycle.id,
            {},
            (PlannedQuery(index + 1, "synthetic", ProviderIntent.EXACT, "synthetic"),),
            (identity,),
            "test",
            "test",
            "test",
        )
        execution = __import__("asyncio").run(service.execute(plan))
        service.finalize(execution)
        executions.append(execution)
        cycle = DiscoveryRepository(db_session).get_cycle_for_run(run.id)
        cycles.append((cycle.status, cycle.error_code, dict(cycle.stats_json)))

    assert [item.board_verification_counts for item in executions] == [
        (1, 0, 0),
        (0, 1, 0),
        (0, 0, 1),
        (0, 0, 0),
    ]
    assert executions[-1].verified_batches[0].jobs is accepted_jobs
    assert all(status is DiscoveryCycleStatus.COMPLETED for status, _, _ in cycles)
    assert all(error_code is None for _, error_code, _ in cycles)
    assert [
        tuple(
            stats[key]
            for key in (
                "board_verification_failed",
                "board_verification_empty",
                "board_verification_invalid_fields",
            )
        )
        for _, _, stats in cycles
    ] == [(1, 0, 0), (0, 1, 0), (0, 0, 1), (0, 0, 0)]
    no_verification = DiscoveryPlan(
        plan.run_id, plan.cycle_id, {}, (), (), "test", "test", "test"
    )
    no_verification_execution = __import__("asyncio").run(service.execute(no_verification))
    assert no_verification_execution.board_verification_counts == (0, 0, 0)


def test_reused_cycle_preserves_historical_stats_without_verification(db_session) -> None:
    from role_radar.discovery.contracts import DiscoveryPlan
    from role_radar.domain.enums import DiscoveryCycleStatus, DiscoveryMode
    from role_radar.repositories.discovery import DiscoveryRepository
    from role_radar.services.pipeline_discovery import PipelineDiscoveryService

    run = RunRepository(db_session).create_run(
        "synthetic", discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    run_id = run.id
    historical_stats = {"known": 1, "verified_sources": 0, "legacy_metric": 7}
    cycle = DiscoveryRepository(db_session).create_cycle(
        run_id=run_id,
        profile_snapshot={},
        planner_version="test",
        planner_hash="test",
        policy_version="test",
        status=DiscoveryCycleStatus.REUSED,
    )
    cycle.stats_json = historical_stats.copy()
    db_session.commit()
    cycle_id = cycle.id

    class NeverCalled:
        async def search(self, _request):
            raise AssertionError("reused execution must not call the provider")

        async def collect(self, _snapshot, _runtime):
            raise AssertionError("reused execution must not call the collector")

    service = PipelineDiscoveryService(
        lambda: db_session,
        provider=NeverCalled(),
        collector_factory=lambda _snapshot: NeverCalled(),
    )
    plan = DiscoveryPlan(
        run.id, cycle_id, {}, (), (), "test", "test", "test", reused=True
    )

    execution = __import__("asyncio").run(service.execute(plan))
    service.finalize(execution)

    persisted = DiscoveryRepository(db_session).get_cycle_for_run(run_id)
    assert persisted.status is DiscoveryCycleStatus.REUSED
    assert persisted.error_code is None
    assert persisted.stats_json == historical_stats
    assert not any(key.startswith("board_verification_") for key in persisted.stats_json)
