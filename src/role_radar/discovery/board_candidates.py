"""Pure classification, canonical identity, and global board deduplication."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Literal

from role_radar.discovery.contracts import (
    GreenhouseOfficialCandidate,
    KnownOfficialCandidate,
    LeverOfficialCandidate,
    SearchResponse,
    TransientSearchHit,
)
from role_radar.discovery.url_classifier import classify_url
from role_radar.sources.identity import canonical_source_key

MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN = 10
MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN = 8

ProviderName = Literal["brave", "tavily"]


class BoardCandidateError(ValueError):
    """Sanitized, stable error for malformed transient candidate input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class BoardSearchHitV2:
    """Search-hit identity needed for deterministic candidate ordering."""

    query_ordinal: int
    provider: ProviderName
    rank: int
    url: str


@dataclass(frozen=True, slots=True)
class BoardSearchBatchV2:
    """Convenience DTO for a bounded provider response."""

    query_ordinal: int
    provider: ProviderName
    hits: tuple[TransientSearchHit, ...]


@dataclass(frozen=True, slots=True)
class BoardCandidateV2:
    """A known official board, before any collector/network work."""

    source_type: Literal["greenhouse", "lever"]
    source_key: str
    configuration: Mapping[str, str]
    canonical_url: str
    query_ordinal: int
    provider: ProviderName
    rank: int
    ordinal: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "configuration", MappingProxyType(dict(self.configuration)))

    @property
    def board_candidate_ordinal(self) -> int:
        return self.ordinal


def _provider_rank(provider: str) -> int:
    if provider == "brave":
        return 0
    if provider == "tavily":
        return 1
    raise BoardCandidateError("discovery_candidate_provider_invalid")


def _known_candidate(
    classified: KnownOfficialCandidate,
    *,
    query_ordinal: int,
    provider: ProviderName,
    rank: int,
) -> BoardCandidateV2:
    if not 1 <= query_ordinal <= 4 or rank <= 0:
        raise BoardCandidateError("discovery_candidate_invalid")
    if isinstance(classified, GreenhouseOfficialCandidate):
        source_type: Literal["greenhouse", "lever"] = "greenhouse"
    elif isinstance(classified, LeverOfficialCandidate):
        source_type = "lever"
    else:
        raise BoardCandidateError("discovery_candidate_invalid")
    configuration = dict(classified.configuration)
    try:
        source_key = canonical_source_key(source_type, configuration)
    except (TypeError, ValueError) as exc:
        raise BoardCandidateError("discovery_candidate_invalid") from exc
    return BoardCandidateV2(
        source_type=source_type,
        source_key=source_key,
        configuration=configuration,
        canonical_url=classified.canonical_url,
        query_ordinal=query_ordinal,
        provider=provider,
        rank=rank,
    )


def classify_board_search_hit(hit: BoardSearchHitV2) -> BoardCandidateV2 | None:
    """Classify one transient hit; unknown/rejected URLs return ``None``."""

    if not isinstance(hit, BoardSearchHitV2):
        raise TypeError("classify_board_search_hit requires BoardSearchHitV2")
    _provider_rank(hit.provider)
    classified = classify_url(hit.url)
    if not isinstance(classified, (GreenhouseOfficialCandidate, LeverOfficialCandidate)):
        return None
    return _known_candidate(
        classified,
        query_ordinal=hit.query_ordinal,
        provider=hit.provider,
        rank=hit.rank,
    )


def classify_board_candidates(hits: Iterable[BoardSearchHitV2]) -> tuple[BoardCandidateV2, ...]:
    """Classify and deterministically order all known official hits."""

    found = [candidate for hit in hits if (candidate := classify_board_search_hit(hit)) is not None]
    return tuple(sorted(found, key=_candidate_order))


def _candidate_order(candidate: BoardCandidateV2) -> tuple[int, int, int, str]:
    return (
        candidate.query_ordinal,
        _provider_rank(candidate.provider),
        candidate.rank,
        candidate.canonical_url,
    )


def deduplicate_board_candidates(
    candidates: Iterable[BoardCandidateV2],
) -> tuple[BoardCandidateV2, ...]:
    """Globally first-wins deduplicate, then retain the first ten boards."""

    ordered = sorted(candidates, key=_candidate_order)
    unique: list[BoardCandidateV2] = []
    seen: set[str] = set()
    for candidate in ordered:
        if candidate.source_key in seen:
            continue
        seen.add(candidate.source_key)
        unique.append(replace(candidate, ordinal=len(unique) + 1))
        if len(unique) == MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN:
            break
    return tuple(unique)


def collect_board_candidates(hits: Iterable[BoardSearchHitV2]) -> tuple[BoardCandidateV2, ...]:
    """Classify, globally deduplicate, and apply the post-dedup ten cap."""

    return deduplicate_board_candidates(classify_board_candidates(hits))


def select_board_verification_candidates(
    candidates: Iterable[BoardCandidateV2],
) -> tuple[BoardCandidateV2, ...]:
    """Select at most the first eight already-retained unique boards."""

    ordered = tuple(candidates)
    if len(ordered) > MAX_UNIQUE_BOARD_CANDIDATES_PER_RUN:
        raise BoardCandidateError("discovery_candidate_invalid")
    return ordered[:MAX_UNIQUE_BOARD_VERIFICATIONS_PER_RUN]


def _batch_hits(batch: BoardSearchBatchV2) -> tuple[BoardSearchHitV2, ...]:
    return tuple(
        BoardSearchHitV2(batch.query_ordinal, batch.provider, hit.rank, hit.url)
        for hit in batch.hits
    )


def board_candidates_from_batches(
    batches: Iterable[BoardSearchBatchV2],
) -> tuple[BoardCandidateV2, ...]:
    """Convenience composition for provider responses with query ordinals."""

    hits: list[BoardSearchHitV2] = []
    for batch in batches:
        if not isinstance(batch, BoardSearchBatchV2):
            raise TypeError("board_candidates_from_batches requires BoardSearchBatchV2")
        hits.extend(_batch_hits(batch))
    return collect_board_candidates(hits)


def board_candidates_from_search_responses(
    responses: Iterable[tuple[int, SearchResponse]],
) -> tuple[BoardCandidateV2, ...]:
    """Convert existing transient responses without persisting their bodies."""

    batches: list[BoardSearchBatchV2] = []
    for query_ordinal, response in responses:
        if not isinstance(response, SearchResponse):
            raise TypeError("responses must contain SearchResponse values")
        if response.provider not in {"brave", "tavily"}:
            raise BoardCandidateError("discovery_candidate_provider_invalid")
        batches.append(BoardSearchBatchV2(query_ordinal, response.provider, tuple(response.hits)))
    return board_candidates_from_batches(batches)


# Clear compatibility spellings for consumers that describe the operation as
# retaining boards rather than collecting them.  They all share one algorithm.
retain_board_candidates = collect_board_candidates
deduplicate_and_cap_board_candidates = deduplicate_board_candidates
build_board_candidates = collect_board_candidates
classify_and_deduplicate_board_candidates = collect_board_candidates
