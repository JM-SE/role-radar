"""Contratos internos del proveedor LLM, independientes del transporte."""

from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

type JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None
FinishReason = Literal["stop", "length", "content_filter", "unknown"]


class LLMMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1)


class StructuredGenerationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str = Field(min_length=1)
    input_hash: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    corrective_attempt: Literal[0, 1]
    messages: tuple[LLMMessage, ...] = Field(min_length=1, max_length=64)
    response_schema: dict[str, JsonValue]
    capability: str = Field(min_length=1)
    trace: dict[str, str] = Field(default_factory=dict, max_length=16)
    generation: dict[str, JsonValue] | None = None

    @field_validator("trace")
    @classmethod
    def trace_values_are_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {
            "job_id",
            "extraction_id",
            "deep_evaluation_id",
            "score_id",
            "prompt_version",
            "schema_version",
        }
        if any(key not in allowed for key in value):
            raise ValueError("trace contains unsupported metadata")
        if any(len(item) > 256 for item in value.values()):
            raise ValueError("trace values are too long")
        return value

    @model_validator(mode="after")
    def operation_id_is_not_transport_metadata(self) -> "StructuredGenerationRequest":
        return self


class StructuredGenerationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content: str
    provider_task_id: str | None = None
    model_identifier: str | None = None
    finish_reason: FinishReason = "unknown"
    usage: dict[str, int] = Field(default_factory=dict)

    @field_validator("usage")
    @classmethod
    def usage_is_sanitized(cls, value: dict[str, int]) -> dict[str, int]:
        allowed = {"prompt_tokens", "completion_tokens", "total_tokens"}
        if any(key not in allowed for key in value):
            raise ValueError("usage contains unsupported counters")
        if any(not isinstance(item, int) or item < 0 for item in value.values()):
            raise ValueError("usage counters must be non-negative integers")
        return value


class LLMProvider(Protocol):
    async def generate_structured(
        self, request: StructuredGenerationRequest
    ) -> StructuredGenerationResult: ...


class ProviderError(Exception):
    """Error público sanitizado del provider; nunca contiene body ni contenido."""

    def __init__(
        self,
        *,
        kind: str,
        error_class: str | None = None,
        code: str | None = None,
        retryable: bool = False,
        provider_task_id: str | None = None,
        status: int | None = None,
    ) -> None:
        self.kind = kind
        self.error_class = error_class or kind
        self.code = code or kind
        self.retryable = retryable
        self.provider_task_id = provider_task_id
        self.status = status
        super().__init__(f"provider error: {self.kind}/{self.code}")
