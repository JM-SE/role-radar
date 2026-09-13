"""E2E dual-route offline: dos rutas lógicas, una sola serie global (Slice B)."""

from __future__ import annotations

import itertools
import json

import pytest

from role_radar.broker.fake import FakeLLMProvider
from role_radar.broker.protocols import LLMMessage, LLMProvider, StructuredGenerationRequest


class RoutedDualProvider(LLMProvider):
    """Fake enrutado solo para tests: capability -> backend con serie global."""

    def __init__(self) -> None:
        self._series = itertools.count(1)
        self._routes: dict[str, FakeLLMProvider] = {}
        self.calls: list[tuple[int, str, str]] = []

    def mount(self, capability: str, backend: str, content: dict) -> None:
        del backend
        self._routes[capability] = FakeLLMProvider(
            responses=[json.dumps(content) for _ in range(8)]
        )

    async def generate_structured(self, request: StructuredGenerationRequest):
        provider = self._routes[request.capability]
        sequence = next(self._series)
        backend = (
            "role-radar-instruct"
            if request.capability == "structured-extraction"
            else "role-radar-thinking"
        )
        self.calls.append((sequence, request.capability, backend))
        return await provider.generate_structured(request)


def _request(capability: str, operation_id: str) -> StructuredGenerationRequest:
    return StructuredGenerationRequest(
        operation_id=operation_id,
        input_hash="b" * 64,
        prompt_version="p1",
        schema_version="s1",
        corrective_attempt=0,
        messages=(LLMMessage(role="user", content="description"),),
        response_schema={"type": "object"},
        capability=capability,
    )


@pytest.mark.asyncio
async def test_dual_route_uses_distinct_backends_with_one_global_series() -> None:
    router = RoutedDualProvider()
    router.mount("structured-extraction", "role-radar-instruct", {"title": "Backend"})
    router.mount("deep-job-evaluation", "role-radar-thinking", {"decision": "review"})

    first = await router.generate_structured(_request("structured-extraction", "job-1"))
    second = await router.generate_structured(_request("deep-job-evaluation", "job-1"))
    third = await router.generate_structured(_request("structured-extraction", "job-2"))

    assert json.loads(first.content) == {"title": "Backend"}
    assert json.loads(second.content) == {"decision": "review"}
    assert json.loads(third.content) == {"title": "Backend"}
    assert router.calls == [
        (1, "structured-extraction", "role-radar-instruct"),
        (2, "deep-job-evaluation", "role-radar-thinking"),
        (3, "structured-extraction", "role-radar-instruct"),
    ]
    sequences = [sequence for sequence, _, _ in router.calls]
    assert sequences == sorted(sequences) == [1, 2, 3]
