"""Builders puros y versionados de mensajes de extracción."""

import json
from typing import Any

from role_radar.broker.protocols import LLMMessage

PROMPT_VERSION = "job-extraction-1"
MAX_PREVIOUS_OUTPUT_BYTES = 8 * 1024


def _context(title: str, company: str, location: str | None) -> str:
    return json.dumps(
        {"title": title, "company": company, "location": location},
        ensure_ascii=False,
        separators=(",", ":"),
    )


def build_extraction_messages(
    *,
    title: str,
    company: str,
    location: str | None,
    description: str,
    response_schema: dict[str, Any],
) -> tuple[LLMMessage, ...]:
    system = (
        "Return JSON only matching the supplied schema. Extract only facts supported by "
        "the job description. Use unknown or not_specified rather than inventing values. "
        "Every meaningful scalar and every list item must include a literal evidence quote. "
        "Trusted title, company and location are context and must not be emitted as fields."
    )
    user = (
        f"Trusted context: {_context(title, company, location)}\n"
        f"Description:\n{description}\n"
        "JSON Schema:\n"
        f"{json.dumps(response_schema, ensure_ascii=False, separators=(',', ':'))}"
    )
    return (LLMMessage(role="system", content=system), LLMMessage(role="user", content=user))


def build_corrective_messages(
    *,
    title: str,
    company: str,
    location: str | None,
    description: str,
    response_schema: dict[str, Any],
    errors: tuple[str, ...] | list[str],
    previous_output: str | None = None,
) -> tuple[LLMMessage, ...]:
    safe_errors = "; ".join(item[:256] for item in errors[:16])
    previous = (previous_output or "")[:MAX_PREVIOUS_OUTPUT_BYTES]
    correction = (
        "Correct the previous JSON. Output JSON only, with no explanation. Fix only these "
        f"sanitized issues: {safe_errors}.\nPrevious output (untrusted, bounded): {previous}"
    )
    base = build_extraction_messages(
        title=title,
        company=company,
        location=location,
        description=description,
        response_schema=response_schema,
    )
    return (base[0], LLMMessage(role="user", content=f"{base[1].content}\n{correction}"))
