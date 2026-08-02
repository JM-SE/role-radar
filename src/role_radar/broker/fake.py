"""Proveedor LLM determinista para desarrollo y tests completamente offline."""

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from role_radar.broker.protocols import (
    LLMProvider,
    ProviderError,
    StructuredGenerationRequest,
    StructuredGenerationResult,
)

_DEFAULT_CONTENT = json.dumps(
    {
        "seniority": {"state": "unknown", "value": None, "evidence": None},
        "remote_policy": {"state": "unknown", "value": None, "evidence": None},
        "regions": [],
        "employment_type": {"state": "unknown", "value": None, "evidence": None},
        "required_skills": [],
        "preferred_skills": [],
        "languages": [],
        "years_experience": {"state": "unknown", "value": None, "evidence": None},
        "salary": {
            "state": "unknown",
            "min": None,
            "max": None,
            "currency": None,
            "period": None,
            "evidence": None,
        },
        "work_authorization": {"state": "unknown", "value": None, "evidence": None},
    },
    ensure_ascii=False,
)


class FakeLLMProvider(LLMProvider):
    """Responde con una secuencia configurada y registra llamadas para asserts."""

    def __init__(
        self,
        responses: Iterable[StructuredGenerationResult | ProviderError | str | dict[str, Any]]
        | None = None,
        *,
        result: StructuredGenerationResult | str | dict[str, Any] | None = None,
        error: ProviderError | None = None,
        fixture: str | Path | dict[str, Any] | None = None,
    ) -> None:
        configured: list[StructuredGenerationResult | ProviderError] = []
        if responses is not None:
            configured.extend(self._coerce(item) for item in responses)
        elif error is not None:
            configured.append(error)
        elif result is not None:
            configured.append(self._coerce(result))
        elif fixture is not None:
            configured.append(self._coerce_fixture(fixture))
        self._responses = configured
        self.requests: list[StructuredGenerationRequest] = []
        self.call_count = 0

    @staticmethod
    def _coerce_fixture(fixture: str | Path | dict[str, Any]) -> StructuredGenerationResult:
        if isinstance(fixture, (str, Path)):
            content = Path(fixture).read_text() if isinstance(fixture, Path) else fixture
            if isinstance(fixture, str) and fixture.lstrip().startswith("{"):
                return StructuredGenerationResult(content=content)
            content = Path(fixture).read_text()
            return StructuredGenerationResult(content=content)
        return StructuredGenerationResult(content=json.dumps(fixture, ensure_ascii=False))

    @staticmethod
    def _coerce(
        value: StructuredGenerationResult | ProviderError | str | dict[str, Any],
    ) -> StructuredGenerationResult | ProviderError:
        if isinstance(value, ProviderError | StructuredGenerationResult):
            return value
        if isinstance(value, dict):
            return StructuredGenerationResult(content=json.dumps(value, ensure_ascii=False))
        return StructuredGenerationResult(content=value)

    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult:
        self.requests.append(request)
        self.call_count += 1
        response = (
            self._responses[self.call_count - 1]
            if self.call_count <= len(self._responses)
            else None
        )
        if response is None:
            return StructuredGenerationResult(content=_DEFAULT_CONTENT)
        if isinstance(response, ProviderError):
            raise response
        return response
