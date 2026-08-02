"""El fake es determinista, secuencial y nunca abre red."""

import json

import pytest

from role_radar.broker.fake import FakeLLMProvider
from role_radar.broker.protocols import LLMMessage, ProviderError, StructuredGenerationRequest


def _request() -> StructuredGenerationRequest:
    return StructuredGenerationRequest(
        operation_id="job-1",
        input_hash="a" * 64,
        prompt_version="p1",
        schema_version="s1",
        corrective_attempt=0,
        messages=(LLMMessage(role="user", content="description"),),
        response_schema={"type": "object"},
        capability="structured-extraction",
    )


@pytest.mark.asyncio
async def test_fake_sequence_and_call_count() -> None:
    error = ProviderError(kind="output_invalid", code="bad_json")
    provider = FakeLLMProvider(responses=[error, {"ok": True}])
    with pytest.raises(ProviderError):
        await provider.generate_structured(_request())
    result = await provider.generate_structured(_request())
    assert json.loads(result.content) == {"ok": True}
    assert provider.call_count == 2
    assert len(provider.requests) == 2
