"""Superficie determinista de relevancia sobre candidatos de discovery."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

RELEVANCE_VERSION: Final = "relevance-v1"
MAX_RELEVANT_JOBS: Final = 20
MAX_NEAR_MISS_JOBS: Final = 20

RELEVANT: Final = "relevant"
NEAR_MISS: Final = "near_miss"
UNRELATED: Final = "unrelated"


@dataclass(frozen=True, slots=True)
class RelevanceCandidate:
    """Texto mínimo necesario para clasificar un candidato."""

    job_id: str
    title: str
    company: str
    description: str


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    """Candidato clasificado con sus frases coincidentes."""

    job_id: str
    band: str
    matched_phrases: tuple[str, ...]
    text_sha256: str


@dataclass(frozen=True, slots=True)
class RelevanceSurface:
    """Resultado acotado y determinista de relevance-v1."""

    relevance_version: str
    approved_phrases: tuple[str, ...]
    relevant: tuple[RankedCandidate, ...]
    near_miss: tuple[RankedCandidate, ...]
    unrelated_count: int
    excluded_count: int


def _normalize(text: str) -> str:
    return " ".join(text.casefold().split())


def _text_sha256(title: str, description: str) -> str:
    digest = sha256()
    digest.update(_normalize(title).encode("utf-8"))
    digest.update(b"\x00")
    digest.update(_normalize(description).encode("utf-8"))
    return digest.hexdigest()


def rank_candidates(
    candidates: Iterable[RelevanceCandidate],
    *,
    approved_phrases: Sequence[str],
) -> RelevanceSurface:
    """Clasifica candidatos con coincidencia literal de frases aprobadas.

    relevant si hay 2+ frases distintas o al menos una en el título;
    near_miss si hay exactamente una frase solo en la descripción;
    unrelated en otro caso. Sin etiquetas, puntajes ni LLM.
    """

    phrases = tuple(dict.fromkeys(phrase for phrase in approved_phrases if phrase))
    relevant: list[RankedCandidate] = []
    near_miss: list[RankedCandidate] = []
    unrelated_count = 0
    excluded_count = 0
    for candidate in candidates:
        if (
            not candidate.job_id
            or not candidate.title.strip()
            or not candidate.company.strip()
            or not candidate.description.strip()
        ):
            excluded_count += 1
            continue
        folded_title = candidate.title.casefold()
        folded_description = candidate.description.casefold()
        title_hits = tuple(phrase for phrase in phrases if phrase.casefold() in folded_title)
        description_hits = tuple(
            phrase for phrase in phrases if phrase.casefold() in folded_description
        )
        matched = tuple(dict.fromkeys((*title_hits, *description_hits)))
        ranked = RankedCandidate(
            job_id=candidate.job_id,
            band=UNRELATED,
            matched_phrases=matched,
            text_sha256=_text_sha256(candidate.title, candidate.description),
        )
        if len(matched) >= 2 or len(title_hits) >= 1:
            relevant.append(
                RankedCandidate(
                    job_id=ranked.job_id,
                    band=RELEVANT,
                    matched_phrases=ranked.matched_phrases,
                    text_sha256=ranked.text_sha256,
                )
            )
        elif len(matched) == 1:
            near_miss.append(
                RankedCandidate(
                    job_id=ranked.job_id,
                    band=NEAR_MISS,
                    matched_phrases=ranked.matched_phrases,
                    text_sha256=ranked.text_sha256,
                )
            )
        else:
            unrelated_count += 1
    relevant.sort(key=lambda item: (-len(item.matched_phrases), item.job_id))
    near_miss.sort(key=lambda item: (-len(item.matched_phrases), item.job_id))
    return RelevanceSurface(
        relevance_version=RELEVANCE_VERSION,
        approved_phrases=phrases,
        relevant=tuple(relevant[:MAX_RELEVANT_JOBS]),
        near_miss=tuple(near_miss[:MAX_NEAR_MISS_JOBS]),
        unrelated_count=unrelated_count,
        excluded_count=excluded_count,
    )
