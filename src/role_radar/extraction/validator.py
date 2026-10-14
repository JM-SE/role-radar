"""Validación pura de semántica y evidencia de una extracción."""

import re
import unicodedata
from collections.abc import Iterable

from role_radar.extraction.schemas import (
    EvidenceItem,
    IntegerEvidence,
    JobExtractionPayload,
    SalaryEvidence,
    TextEvidence,
)
from role_radar.normalization.text import normalize_whitespace

# Evidence tiers: Tier 1 is the strict rule (whitespace + case). Tier 2 accepts
# near-literal citations from small models that paraphrase connectors or drop
# interior filler while keeping content words in order ("&" vs "and", "Develop
# & improve" vs "develop and improve"). It folds ASCII punctuation, drops a
# small connector stopword set, and requires the evidence content tokens to
# appear in the description IN ORDER (gaps allowed). Invented quotes still fail
# (their content words are absent) and wrong-order salad fails. Right-order
# salad passes: accepted MVP tradeoff, documented here.
_FOLD_PUNCT = re.compile(r"[^\w\s]")

_CONNECTORS = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "in",
        "on",
        "at",
        "to",
        "for",
        "with",
        "by",
        "from",
        "as",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "it",
        "its",
        "this",
        "that",
        "these",
        "those",
    }
)


def _fold(value: str) -> str:
    text = unicodedata.normalize("NFKC", value).casefold()
    text = _FOLD_PUNCT.sub(" ", text)
    return normalize_whitespace(text)


def _normal(value: str) -> str:
    return normalize_whitespace(value).casefold()


def _content_tokens(value: str) -> tuple[str, ...]:
    return tuple(token for token in _fold(value).split() if token not in _CONNECTORS)


def _ordered_subsequence(needle: tuple[str, ...], haystack: list[str]) -> bool:
    position = 0
    for token in needle:
        while position < len(haystack) and haystack[position] != token:
            position += 1
        if position == len(haystack):
            return False
        position += 1
    return True


def _evidence_found(evidence: str, description: str) -> bool:
    if _normal(evidence) in _normal(description):
        return True
    needle = _content_tokens(evidence)
    if not needle:
        return False
    return _ordered_subsequence(needle, _fold(description).split())


def _check_scalar(name: str, value: TextEvidence | IntegerEvidence, description: str) -> list[str]:
    errors: list[str] = []
    if value.state == "specified":
        if value.value is None:
            errors.append(f"{name}.value_missing")
        if not value.evidence or not value.evidence.strip():
            errors.append(f"{name}.evidence_missing")
        elif not _evidence_found(value.evidence, description):
            errors.append(f"{name}.evidence_not_found")
    elif value.value is not None:
        errors.append(f"{name}.value_for_{value.state}")
    elif value.evidence not in (None, ""):
        errors.append(f"{name}.evidence_for_{value.state}")
    if isinstance(value, IntegerEvidence) and value.value is not None and value.value < 0:
        errors.append(f"{name}.negative")
    return errors


def _check_items(name: str, items: Iterable[EvidenceItem], description: str) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if item.state != "specified":
            continue
        normalized = _normal(item.value)
        if normalized in seen:
            errors.append(f"{name}[{index}].duplicate")
        seen.add(normalized)
        if item.evidence is None or not _evidence_found(item.evidence, description):
            errors.append(f"{name}[{index}].evidence_not_found")
    return errors


def _check_salary(salary: SalaryEvidence, description: str) -> list[str]:
    errors: list[str] = []
    if salary.state == "specified":
        if salary.min is None and salary.max is None:
            errors.append("salary.value_missing")
        if not salary.evidence or not salary.evidence.strip():
            errors.append("salary.evidence_missing")
        elif not _evidence_found(salary.evidence, description):
            errors.append("salary.evidence_not_found")
    elif any(
        value is not None for value in (salary.min, salary.max, salary.currency, salary.period)
    ):
        errors.append(f"salary.value_for_{salary.state}")
    if salary.currency and salary.min is None and salary.max is None:
        errors.append("salary.currency_without_value")
    if salary.min is not None and salary.max is not None and salary.min > salary.max:
        errors.append("salary.range_incoherent")
    return errors


def validate_extraction(
    payload: JobExtractionPayload,
    description: str,
    *,
    trusted_context: dict[str, str | None] | None = None,
) -> tuple[str, ...]:
    """Devuelve códigos estables; no devuelve contenido inválido ni PII."""
    del trusted_context  # Trusted context is prompt input, never an output field.
    errors: list[str] = []
    for name in ("seniority", "remote_policy", "employment_type", "work_authorization"):
        errors.extend(_check_scalar(name, getattr(payload, name), description))
    errors.extend(_check_scalar("years_experience", payload.years_experience, description))
    for name in ("regions", "required_skills", "preferred_skills", "languages"):
        errors.extend(_check_items(name, getattr(payload, name), description))
    errors.extend(_check_salary(payload.salary, description))
    return tuple(errors)


def validate_payload(
    payload: JobExtractionPayload,
    description: str,
    *,
    trusted_context: dict[str, str | None] | None = None,
) -> tuple[str, ...]:
    return validate_extraction(payload, description, trusted_context=trusted_context)
