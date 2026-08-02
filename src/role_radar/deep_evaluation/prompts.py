"""Versioned, concise prompts. They request conclusions, never chain of thought."""

from role_radar.broker.protocols import LLMMessage

PROMPT_VERSION = "deep-prompt-v1"


def build_deep_messages(
    *, input_json: str, response_schema: dict[str, object]
) -> tuple[LLMMessage, ...]:
    return (
        LLMMessage(
            role="system",
            content=(
                "Return only the requested JSON. Give brief conclusions and cite supplied "
                "evidence. Do not reveal private reasoning or chain of thought."
            ),
        ),
        LLMMessage(
            role="user",
            content=(
                "Evaluate this structured job input. Do not add fields, HTML, URLs, or "
                f"reasoning text.\nINPUT_JSON:\n{input_json}\nSCHEMA:\n{response_schema}"
            ),
        ),
    )


def build_corrective_messages(
    *, input_json: str, response_schema: dict[str, object], errors: tuple[str, ...]
) -> tuple[LLMMessage, ...]:
    return (
        LLMMessage(
            role="system",
            content=(
                "Return only valid JSON matching the schema. Correct only the listed "
                "validation errors; do not reveal reasoning."
            ),
        ),
        LLMMessage(
            role="user",
            content=(
                f"Validation codes: {', '.join(errors)}\nINPUT_JSON:\n{input_json}"
                f"\nSCHEMA:\n{response_schema}"
            ),
        ),
    )
