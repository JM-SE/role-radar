from role_radar.execution_budget import (
    CANARY_BUDGET,
    CanaryAmbiguousAttempt,
    CanaryDeferred,
    CanaryExecutionBudget,
    activate_canary_budget,
    reset_canary_budget,
)
from role_radar.repositories.runs import RunRepository


def _broker_request(*, capability="structured-extraction", corrective_attempt=0):
    from role_radar.broker.protocols import LLMMessage, StructuredGenerationRequest

    return StructuredGenerationRequest(
        operation_id="job-1",
        input_hash="a" * 64,
        prompt_version="p1",
        schema_version="s1",
        corrective_attempt=corrective_attempt,
        messages=(LLMMessage(role="user", content="safe description"),),
        response_schema={"type": "object", "properties": {}},
        capability=capability,
        trace={"job_id": "job-1", "prompt_version": "p1"},
    )

def test_broker_poll_attempts_consume_shared_wire_budget_before_io(db_session) -> None:
    import asyncio

    import httpx

    from role_radar.broker.client import LLMBrokerClient
    from role_radar.broker.protocols import LLMMessage, StructuredGenerationRequest

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    token = activate_canary_budget(CanaryExecutionBudget(lambda: db_session, run_id))
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(202, json={"id": "task-1"})
        return httpx.Response(200, json={"status": "pending"})

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = LLMBrokerClient(
                base_url="http://broker.invalid",
                token="test-token",
                poll_interval_seconds=0.001,
                result_timeout_seconds=1,
                http_client=http_client,
            )
            request = StructuredGenerationRequest(
                operation_id="job-1",
                input_hash="a" * 64,
                prompt_version="p1",
                schema_version="s1",
                corrective_attempt=0,
                messages=(LLMMessage(role="user", content="safe description"),),
                response_schema={"type": "object", "properties": {}},
                capability="structured-extraction",
                trace={"job_id": "job-1", "prompt_version": "p1"},
            )
            try:
                await client.generate_structured(request)
            except CanaryDeferred:
                return
            raise AssertionError("the fifth Broker wire attempt must defer before I/O")

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(token)

    assert calls == 4
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["broker_attempts"] == 4
    assert persisted.canary_checkpoint_json["counts"]["broker_calls"] == 1

def test_broker_corrective_and_capability_calls_share_four_call_and_wire_limits(
    db_session,
) -> None:
    import asyncio

    import httpx

    from role_radar.broker.client import LLMBrokerClient

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    budget_token = activate_canary_budget(CanaryExecutionBudget(lambda: db_session, run_id))
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "status": "succeeded",
                "result": {
                    "content": "{}",
                    "finish_reason": "stop",
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                },
            },
        )

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            extraction = LLMBrokerClient(
                base_url="http://broker.invalid",
                token="test-token",
                capability="structured-extraction",
                http_client=http_client,
            )
            deep = LLMBrokerClient(
                base_url="http://broker.invalid",
                token="test-token",
                capability="deep-job-evaluation",
                http_client=http_client,
            )
            requests = (
                (extraction, _broker_request()),
                (extraction, _broker_request(corrective_attempt=1)),
                (deep, _broker_request(capability="deep-job-evaluation")),
                (
                    deep,
                    _broker_request(
                        capability="deep-job-evaluation", corrective_attempt=1
                    ),
                ),
            )
            for client, request in requests:
                await client.generate_structured(request)
            try:
                await extraction.generate_structured(_broker_request())
            except CanaryDeferred:
                return
            raise AssertionError("the fifth logical call must defer before submit")

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(budget_token)

    assert len(seen) == 4
    assert len({item.headers["Idempotency-Key"] for item in seen}) == 4
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["broker_calls"] == 4
    assert persisted.canary_checkpoint_json["counts"]["broker_attempts"] == 4

def test_broker_submit_retries_use_idempotency_and_consume_one_wire_reservation_each(
    db_session,
) -> None:
    import asyncio

    import httpx

    from role_radar.broker.client import LLMBrokerClient

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    budget_token = activate_canary_budget(CanaryExecutionBudget(lambda: db_session, run_id))
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.content, request.headers["Idempotency-Key"]))
        if len(seen) < 4:
            raise httpx.ReadTimeout("ambiguous submit")
        return httpx.Response(
            200,
            json={
                "status": "succeeded",
                "result": {
                    "content": "{}",
                    "finish_reason": "stop",
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                },
            },
        )

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = LLMBrokerClient(
                base_url="http://broker.invalid",
                token="test-token",
                submit_reconcile_attempts=5,
                http_client=http_client,
            )
            await client.generate_structured(_broker_request())

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(budget_token)

    assert len(seen) == 4
    assert len({body for body, _key in seen}) == 1
    assert len({key for _body, key in seen}) == 1
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["broker_calls"] == 1
    assert persisted.canary_checkpoint_json["counts"]["broker_attempts"] == 4
    assert persisted.canary_checkpoint_json["reservations"] == []
    assert persisted.canary_checkpoint_json["logical_reservations"] == []

def test_broker_submit_retry_ceiling_defers_before_fifth_network_attempt(db_session) -> None:
    import asyncio

    import httpx

    from role_radar.broker.client import LLMBrokerClient

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    budget_token = activate_canary_budget(CanaryExecutionBudget(lambda: db_session, run_id))
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("ambiguous submit")

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = LLMBrokerClient(
                base_url="http://broker.invalid",
                token="test-token",
                submit_reconcile_attempts=5,
                http_client=http_client,
            )
            try:
                await client.generate_structured(_broker_request())
            except CanaryDeferred:
                return
            raise AssertionError("a fifth submit must defer before network I/O")

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(budget_token)

    assert calls == 4
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["broker_calls"] == 1
    assert persisted.canary_checkpoint_json["counts"]["broker_attempts"] == 4
    assert persisted.canary_checkpoint_json["reservations"] == []
    assert len(persisted.canary_checkpoint_json["logical_reservations"]) == 1

def test_broker_crash_reservation_blocks_replay_before_http(db_session) -> None:
    import asyncio

    import httpx

    from role_radar.broker.client import LLMBrokerClient

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    budget = CanaryExecutionBudget(lambda: db_session, run_id)
    unresolved_token = budget.reserve("broker_attempts")
    assert unresolved_token is not None
    budget_token = activate_canary_budget(CanaryExecutionBudget(lambda: db_session, run_id))
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = LLMBrokerClient(
                base_url="http://broker.invalid",
                token="test-token",
                http_client=http_client,
            )
            try:
                await client.generate_structured(_broker_request())
            except CanaryAmbiguousAttempt:
                return
            raise AssertionError("the unresolved request must remain non-replayable")

    try:
        asyncio.run(exercise())
    finally:
        reset_canary_budget(budget_token)

    assert calls == 0
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["reservations"] == [
        {"token": unresolved_token, "kind": "broker_attempts"}
    ]
