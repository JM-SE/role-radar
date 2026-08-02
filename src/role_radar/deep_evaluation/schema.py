"""Strict Thinking response schema and broker guards."""

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt

SCHEMA_VERSION = "deep-evaluation-v1"
MAX_SCHEMA_BYTES = 64 * 1024
_FORBIDDEN = {
    "reasoning",
    "chain_of_thought",
    "cot",
    "analysis",
    "thoughts",
    "scratchpad",
    "hard_blockers",
}


class EvidenceRefV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    source: Literal["extraction", "preliminary_signal", "ambiguity"]
    reference: str = Field(min_length=1, max_length=240)
    excerpt: str = Field(min_length=1, max_length=240)


class EvidencePointV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    summary: str = Field(min_length=1, max_length=240)
    evidence: list[EvidenceRefV1] = Field(min_length=1, max_length=3)


class DeepEvaluationPayloadV1(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)
    fit_score: StrictInt = Field(ge=0, le=100)
    decision: Literal["strong_match", "possible_match", "weak_match", "reject", "needs_review"]
    strengths: list[EvidencePointV1] = Field(max_length=6)
    gaps: list[EvidencePointV1] = Field(max_length=6)
    model_concerns: list[EvidencePointV1] = Field(max_length=6)
    uncertainties: list[EvidencePointV1] = Field(max_length=6)
    recommended_action: Literal["apply", "review", "ignore"]
    confidence: float = Field(ge=0, le=1)


def _walk_forbidden(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).casefold() in _FORBIDDEN or _walk_forbidden(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_walk_forbidden(item) for item in value)
    return False


def get_deep_evaluation_schema() -> dict[str, Any]:
    schema = DeepEvaluationPayloadV1.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    assert_broker_compatible(schema)
    return schema


def assert_broker_compatible(schema: dict[str, Any]) -> None:
    if len(json.dumps(schema, separators=(",", ":")).encode()) > MAX_SCHEMA_BYTES:
        raise ValueError("deep schema exceeds broker size limit")
    refs: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if "$ref" in value and isinstance(value["$ref"], str):
                refs.append(value["$ref"])
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)
    if any(not ref.startswith("#/") for ref in refs):
        raise ValueError("only local schema references are supported")


def validate_deep_payload(value: str | dict[str, Any], input_value: Any) -> DeepEvaluationPayloadV1:
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("payload_invalid") from exc
    else:
        decoded = value
    if not isinstance(decoded, dict) or _walk_forbidden(decoded):
        raise ValueError("payload_forbidden_content")
    payload = DeepEvaluationPayloadV1.model_validate(decoded)
    allowed = {item.reference: item.excerpt for item in input_value.extraction.evidence}
    allowed.update(
        {f"signal[{i}]": str(item) for i, item in enumerate(input_value.preliminary.signals)}
    )
    allowed.update(
        {f"ambiguity[{i}]": str(item) for i, item in enumerate(input_value.preliminary.ambiguities)}
    )
    for point in (
        *payload.strengths,
        *payload.gaps,
        *payload.model_concerns,
        *payload.uncertainties,
    ):
        for ref in point.evidence:
            if ref.reference not in allowed or ref.excerpt != allowed[ref.reference]:
                raise ValueError("evidence_reference_invalid")
    return payload


def deep_evaluation_schema() -> dict[str, Any]:
    """Compatibility alias used by provider adapters and tests."""
    return get_deep_evaluation_schema()
