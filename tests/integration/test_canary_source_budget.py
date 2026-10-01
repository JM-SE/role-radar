from role_radar.execution_budget import (
    CANARY_BUDGET,
    CanaryAmbiguousAttempt,
    CanaryDeferred,
    CanaryExecutionBudget,
    activate_canary_budget,
    reset_canary_budget,
)
from role_radar.repositories.runs import RunRepository


def test_canary_reservations_are_durable_and_an_unresolved_attempt_fails_closed(db_session) -> None:
    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    budget = CanaryExecutionBudget(lambda: db_session, run_id)

    for _ in range(4):
        token = budget.consume("broker_calls")
        assert token is not None
        budget.settle(token)
    assert budget.consume("broker_calls") is None

    token = budget.reserve("source_http_attempts")
    assert token is not None
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["source_http_attempts"] == 1
    try:
        CanaryExecutionBudget(lambda: db_session, run_id).reserve("source_http_attempts")
    except CanaryAmbiguousAttempt:
        pass
    else:
        raise AssertionError("an unresolved side effect must fail closed")

def test_collector_http_retry_attempts_share_the_persisted_canary_ceiling(
    db_session,
) -> None:
    import asyncio

    import httpx

    from role_radar.collectors.bounded_http import BoundedHttpClient
    from role_radar.collectors.policy import HttpPolicy

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    budget = CanaryExecutionBudget(lambda: db_session, run_id)
    token = activate_canary_budget(budget)
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503) if calls == 1 else httpx.Response(200, json={"jobs": []})

    async def no_sleep(_seconds: float) -> None:
        return None

    async def exercise() -> None:
        policy = HttpPolicy(
            origin="https://boards-api.greenhouse.io",
            allowed_path_prefix="/v1/boards/",
            allowed_query_keys=frozenset(),
            max_retries=1,
        )
        async with BoundedHttpClient(
            policy, transport=httpx.MockTransport(handler), sleeper=no_sleep
        ) as client:
            await client.get("/v1/boards/acme/jobs")
            try:
                await client.get("/v1/boards/acme/jobs")
            except CanaryDeferred:
                return
            raise AssertionError("a third source request must be deferred")

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(token)

    assert calls == 2
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["source_http_attempts"] == 2

def test_search_and_collector_http_clients_share_two_attempt_ceiling(db_session) -> None:
    import asyncio

    import httpx

    from role_radar.collectors.bounded_http import BoundedHttpClient
    from role_radar.collectors.policy import HttpPolicy
    from role_radar.discovery.contracts import ProviderIntent, SearchRequest
    from role_radar.discovery.providers.bounded_http import BoundedSearchHttpClient

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    token = activate_canary_budget(CanaryExecutionBudget(lambda: db_session, run_id))
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={"web": []},
            headers={"content-type": "application/json"},
        )

    async def no_sleep(_seconds: float) -> None:
        return None

    async def exercise() -> None:
        request = SearchRequest(
            operation_key="cycle:query:1",
            query="profile-derived role query",
            query_key="query-key",
            planner_version="planner-v1",
            query_version="policy-v1",
            provider_intent=ProviderIntent.EXACT,
        )
        async with BoundedSearchHttpClient(transport=httpx.MockTransport(handler)) as search:
            await search.request("GET", "https://search.invalid/query", request, headers={})
        policy = HttpPolicy(
            origin="https://boards-api.greenhouse.io",
            allowed_path_prefix="/v1/boards/",
            allowed_query_keys=frozenset(),
        )
        async with BoundedHttpClient(
            policy,
            transport=httpx.MockTransport(handler),
            sleeper=no_sleep,
        ) as collector:
            await collector.get("/v1/boards/acme/jobs")
            try:
                await collector.get("/v1/boards/acme/jobs")
            except CanaryDeferred:
                return
            raise AssertionError("search and collector clients must share the same two attempts")

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(token)

    assert calls == 2
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["source_http_attempts"] == 2

def test_canary_budget_tampering_is_rejected(db_session) -> None:
    run = RunRepository(db_session).create_run("canary")
    changed = {**CANARY_BUDGET, "limits": {**CANARY_BUDGET["limits"], "broker_calls": 5}}
    run.canary_budget_json = changed
    db_session.commit()

    try:
        CanaryExecutionBudget(lambda: db_session, run.id).consume("broker_calls")
    except RuntimeError as error:
        assert str(error) == "canary_budget_missing_or_changed"
    else:
        raise AssertionError("the persisted canary ceilings must be immutable")
