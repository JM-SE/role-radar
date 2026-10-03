"""HTTP task protocol probado únicamente con httpx.MockTransport."""

import json

import httpx
import pytest

from role_radar.broker.client import LLMBrokerClient, derive_idempotency_key
from role_radar.broker.protocols import LLMMessage, StructuredGenerationRequest


def _request() -> StructuredGenerationRequest:
    return StructuredGenerationRequest(
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


def _success(content: str = '{"ok":true}') -> dict[str, object]:
    return {
        "status": "succeeded",
        "result": {
            "content": content,
            "finish_reason": "stop",
            "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
        },
    }


@pytest.mark.asyncio
async def test_immediate_200_uses_exact_safe_submission_contract() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        assert body["workload"] == "role-radar"
        assert body["capability"] == "structured-extraction"
        assert "application" not in body
        assert not {"model", "backend", "provider", "priority"} & set(body)
        assert request.headers["Authorization"] == "Bearer secret"
        assert request.headers["Prefer"] == "wait=10"
        return httpx.Response(200, json=_success())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = LLMBrokerClient(
            base_url="http://broker",
            token="secret",
            http_client=http_client,
        )
        result = await client.generate_structured(_request())
    assert result.provider_task_id is None
    assert len(seen) == 1
    key = seen[0].headers["Idempotency-Key"]
    assert len(key) == 75 and key.isascii()
    assert "secret" not in key


@pytest.mark.asyncio
async def test_202_pending_then_success_polls_without_cancel() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.method == "POST":
            return httpx.Response(202, json={"id": "task-1"})
        return httpx.Response(200, json={"status": "pending"} if calls == 2 else _success())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = LLMBrokerClient(
            base_url="http://broker",
            token="secret",
            poll_interval_seconds=0.001,
            result_timeout_seconds=1,
            http_client=http_client,
        )
        result = await client.generate_structured(_request())
    assert result.content == '{"ok":true}'
    assert calls == 3


@pytest.mark.asyncio
async def test_unknown_submit_replays_same_body_and_key() -> None:
    seen: list[tuple[bytes, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.content, request.headers["Idempotency-Key"]))
        if len(seen) < 3:
            raise httpx.ReadTimeout("unknown")
        return httpx.Response(200, json=_success())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = LLMBrokerClient(
            base_url="http://broker",
            token="secret",
            submit_reconcile_attempts=3,
            http_client=http_client,
        )
        await client.generate_structured(_request())
    assert len(seen) == 3
    assert len({item[0] for item in seen}) == 1
    assert len({item[1] for item in seen}) == 1


@pytest.mark.parametrize("argument", ["http_client", "client"])
@pytest.mark.asyncio
async def test_injected_client_timeout_and_ownership_are_preserved(argument: str) -> None:
    injected = httpx.AsyncClient(timeout=23)
    client = LLMBrokerClient(
        base_url="http://broker",
        token="secret",
        http_timeout_seconds=17,
        **{argument: injected},
    )
    assert client._client is injected
    assert injected.timeout.read == 23
    await client.aclose()
    assert not injected.is_closed
    await injected.aclose()


def test_idempotency_key_changes_by_attempt() -> None:
    first = derive_idempotency_key(
        job_id="j", input_hash="i", prompt_version="p", schema_version="s", corrective_attempt=0
    )
    second = derive_idempotency_key(
        job_id="j", input_hash="i", prompt_version="p", schema_version="s", corrective_attempt=1
    )
    assert first != second
