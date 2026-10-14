"""Builders puros y versionados de mensajes de extracción."""

import json
from typing import Any

from role_radar.broker.protocols import LLMMessage

# v2 (2026-09-17): exact-substring honesty rules. Live evidence on Qwen3-4B-Instruct:
# initial attempt on a Nortal posting dropped 15 validation errors to 2; the 2
# remaining are model-side paraphrase (skill value shortened, evidence sentence
# swapped for a same-meaning one), not validator strictness: the cited strings
# ARE casefold-substrings but NOT exact substrings (case/punctuation drift like
# "javascript" vs "JavaScript", "&" vs "and", missing Oxford comma).
# v3 (2026-09-17): never quote the trusted context line as evidence. Fresh version
# because prompt text feeds broker idempotency keys only via prompt_version.
# v4 (2026-09-17): location removed from trusted context. Live evidence: the model
# quoted "Latin America - Remote" (context-only, absent from all 3 Nortal bodies)
# as regions evidence in 4/4 attempts across 2 jobs, ignoring the v3 rule. Region
# is already decided upstream by intake (exact_region_match); extraction must not
# re-derive it from context it cannot cite.
PROMPT_VERSION = "job-extraction-4"
MAX_PREVIOUS_OUTPUT_BYTES = 8 * 1024


def _context(title: str, company: str) -> str:
    return json.dumps(
        {"title": title, "company": company},
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
        "the job description. Every evidence string must be an exact character-for-character "
        "substring of the description (copy-paste, no paraphrase, no added words, no emoji "
        "that is not adjacent to the quoted words in the description). Quote only the "
        "description: never quote the trusted context line (title, company) as "
        "evidence, even when the words match. When the description "
        "does not state a field literally, use state unknown (or not_specified where the "
        "schema allows it) with value null and evidence null; never invent a value and never "
        "attach an unrelated quote as evidence. Trusted title and company are "
        "context and must not be emitted as fields."
    )
    user = (
        f"Trusted context: {_context(title, company)}\n"
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
        "Correct the previous JSON. Output JSON only, with no explanation. For each listed "
        "field, either quote the exact description substring that states it or set state "
        "unknown with value null and evidence null; do not paraphrase and do not reuse an "
        "unrelated quote. "
        f"Sanitized issues: {safe_errors}.\nPrevious output (untrusted, bounded): {previous}"
    )
    base = build_extraction_messages(
        title=title,
        company=company,
        location=location,
        description=description,
        response_schema=response_schema,
    )
    return (base[0], LLMMessage(role="user", content=f"{base[1].content}\n{correction}"))
