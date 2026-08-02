"""Content validation kept separate from persistence and transport."""

from .input_builder import DeepEvaluationInputV1
from .schema import DeepEvaluationPayloadV1, validate_deep_payload


def validate_result(content: str, input_value: DeepEvaluationInputV1) -> DeepEvaluationPayloadV1:
    return validate_deep_payload(content, input_value)
