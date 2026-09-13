"""Pure relevance-v1 classification over discovery candidates."""

from __future__ import annotations

from role_radar.discovery.relevance import (
    MAX_NEAR_MISS_JOBS,
    MAX_RELEVANT_JOBS,
    RELEVANCE_VERSION,
    RelevanceCandidate,
    rank_candidates,
)

PHRASES = ("Backend Engineer", "Python")


def _candidate(job_id: str, title: str, description: str) -> RelevanceCandidate:
    return RelevanceCandidate(job_id=job_id, title=title, company="Acme", description=description)


def test_relevant_with_two_distinct_phrases() -> None:
    surface = rank_candidates(
        [_candidate("j1", "Java Developer", "Backend Engineer using Python daily")],
        approved_phrases=PHRASES,
    )
    assert surface.relevance_version == RELEVANCE_VERSION
    assert [item.job_id for item in surface.relevant] == ["j1"]
    assert surface.relevant[0].band == "relevant"
    assert surface.relevant[0].matched_phrases == ("Backend Engineer", "Python")
    assert surface.unrelated_count == 0


def test_relevant_with_single_title_hit() -> None:
    surface = rank_candidates(
        [_candidate("j1", "Senior Python Developer", "Java shop with benefits")],
        approved_phrases=PHRASES,
    )
    assert [item.job_id for item in surface.relevant] == ["j1"]
    assert surface.relevant[0].matched_phrases == ("Python",)


def test_near_miss_with_single_description_hit() -> None:
    surface = rank_candidates(
        [_candidate("j1", "Java Developer", "Python is a plus for this role")],
        approved_phrases=PHRASES,
    )
    assert surface.relevant == ()
    assert [item.job_id for item in surface.near_miss] == ["j1"]
    assert surface.near_miss[0].band == "near_miss"


def test_unrelated_without_hits() -> None:
    surface = rank_candidates(
        [_candidate("j1", "Java Developer", "Spring shop with benefits")],
        approved_phrases=PHRASES,
    )
    assert surface.relevant == ()
    assert surface.near_miss == ()
    assert surface.unrelated_count == 1


def test_unrenderable_candidates_are_excluded() -> None:
    surface = rank_candidates(
        [
            RelevanceCandidate(job_id="", title="Python Dev", company="Acme", description="x"),
            RelevanceCandidate(job_id="j2", title="  ", company="Acme", description="Python"),
            RelevanceCandidate(job_id="j3", title="Python Dev", company="  ", description="x"),
            RelevanceCandidate(job_id="j4", title="Python Dev", company="Acme", description="  "),
        ],
        approved_phrases=PHRASES,
    )
    assert surface.excluded_count == 4
    assert surface.relevant == ()
    assert surface.unrelated_count == 0


def test_bounds_and_deterministic_order() -> None:
    candidates = [
        _candidate(f"j{i:03d}", "Python Developer", "Backend Engineer with Python")
        for i in range(MAX_RELEVANT_JOBS + 5)
    ]
    surface = rank_candidates(candidates, approved_phrases=PHRASES)
    assert len(surface.relevant) == MAX_RELEVANT_JOBS
    assert [item.job_id for item in surface.relevant] == [
        f"j{i:03d}" for i in range(MAX_RELEVANT_JOBS)
    ]
    near = [
        _candidate(f"n{i:03d}", "Java Developer", "Python is a plus here")
        for i in range(MAX_NEAR_MISS_JOBS + 3)
    ]
    near_surface = rank_candidates(near, approved_phrases=PHRASES)
    assert len(near_surface.near_miss) == MAX_NEAR_MISS_JOBS


def test_match_order_prefers_richer_hits_then_job_id() -> None:
    surface = rank_candidates(
        [
            _candidate("j2", "Python Developer", "Java shop"),
            _candidate("j1", "Python Developer", "Backend Engineer with Python"),
        ],
        approved_phrases=PHRASES,
    )
    assert [item.job_id for item in surface.relevant] == ["j1", "j2"]


def test_text_hash_is_stable_and_phrases_deduplicated() -> None:
    first = rank_candidates(
        [_candidate("j1", "Python Dev", "Python and python")], approved_phrases=PHRASES
    )
    second = rank_candidates(
        [_candidate("j1", "Python Dev", "Python and python")],
        approved_phrases=["Python", "Python", ""],
    )
    assert first.relevant[0].text_sha256 == second.relevant[0].text_sha256
    assert second.approved_phrases == ("Python",)
