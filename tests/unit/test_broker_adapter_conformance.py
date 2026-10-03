"""Conformancia del adaptador Broker de Role Radar (Slice B, offline)."""

from __future__ import annotations

import pytest

from role_radar.broker.client import LLMBrokerClient
from role_radar.broker.factory import (
    ProviderConfigurationError,
    create_deep_llm_provider,
    create_llm_provider,
)
from role_radar.broker.fake import FakeLLMProvider
from role_radar.broker.protocols import LLMMessage, ProviderError, StructuredGenerationRequest
from role_radar.config import Settings


def _request(capability: str) -> StructuredGenerationRequest:
    return StructuredGenerationRequest(
        operation_id="job-1",
        input_hash="a" * 64,
        prompt_version="p1",
        schema_version="s1",
        corrective_attempt=0,
        messages=(LLMMessage(role="user", content="description"),),
        response_schema={"type": "object"},
        capability=capability,
    )


def test_fake_is_default_without_credentials() -> None:
    settings = Settings()
    assert settings.llm_provider == "fake"
    assert settings.deep_evaluation_provider == "fake"
    assert isinstance(create_llm_provider(settings), FakeLLMProvider)
    assert isinstance(create_deep_llm_provider(settings), FakeLLMProvider)


def test_broker_mode_without_url_and_token_raises_sanitized() -> None:
    settings = Settings(llm_provider="broker", deep_evaluation_provider="broker")
    with pytest.raises(ProviderConfigurationError):
        create_llm_provider(settings)
    with pytest.raises(ProviderConfigurationError):
        create_deep_llm_provider(settings)


@pytest.mark.asyncio
async def test_broker_factories_propagate_http_timeout_to_owned_clients() -> None:
    settings = Settings(
        llm_provider="broker",
        deep_evaluation_provider="broker",
        broker_url="http://localhost:9",
        broker_token="dummy",
        http_timeout_seconds=17,
    )
    extraction = create_llm_provider(settings)
    deep = create_deep_llm_provider(settings)
    assert isinstance(extraction, LLMBrokerClient)
    assert isinstance(deep, LLMBrokerClient)
    try:
        assert extraction._client.timeout.read == 17
        assert deep._client.timeout.read == 17
    finally:
        await extraction.aclose()
        await deep.aclose()


def test_broker_clients_carry_distinct_capabilities() -> None:
    settings = Settings(
        llm_provider="broker",
        deep_evaluation_provider="broker",
        broker_url="http://localhost:9",
        broker_token="dummy",
    )
    extraction = create_llm_provider(settings)
    deep = create_deep_llm_provider(settings)
    assert isinstance(extraction, LLMBrokerClient)
    assert isinstance(deep, LLMBrokerClient)
    # Conformance probe on the binding attribute (behaviorally covered below).
    assert extraction._capability == "structured-extraction"
    assert deep._capability == "deep-job-evaluation"
    assert extraction._capability != deep._capability


@pytest.mark.asyncio
async def test_client_rejects_foreign_capability_before_io() -> None:
    client = LLMBrokerClient(
        base_url="http://localhost:9",
        token="dummy",
        workload="role-radar",
        capability="structured-extraction",
        prefer_wait_seconds=1,
        poll_interval_seconds=1.0,
        result_timeout_seconds=300,
        submit_reconcile_attempts=3,
    )
    try:
        with pytest.raises(ProviderError) as excinfo:
            await client.generate_structured(_request("deep-job-evaluation"))
    finally:
        await client.aclose()
    assert excinfo.value.code == "capability_mismatch"
