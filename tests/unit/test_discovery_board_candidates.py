"""Gate A classification, global deduplication, and cap checks."""

from __future__ import annotations

from role_radar.discovery.board_candidates import (
    BoardSearchHitV2,
    collect_board_candidates,
    select_board_verification_candidates,
)


def test_duplicate_board_across_queries_and_providers_consumes_one_candidate() -> None:
    candidates = collect_board_candidates(
        (
            BoardSearchHitV2(2, "tavily", 1, "https://boards.greenhouse.io/acme"),
            BoardSearchHitV2(1, "brave", 3, "https://boards.greenhouse.io/acme"),
            BoardSearchHitV2(1, "brave", 2, "https://boards.greenhouse.io/other"),
        )
    )
    assert tuple(item.source_key for item in candidates) == (
        "greenhouse:other",
        "greenhouse:acme",
    )
    assert candidates[1].provider == "brave"
    assert candidates[0].ordinal == 1


def test_cap_is_applied_after_global_deduplication() -> None:
    hits = tuple(
        BoardSearchHitV2(
            query_ordinal=1,
            provider="brave",
            rank=index,
            url=f"https://boards.greenhouse.io/board-{index}",
        )
        for index in range(1, 12)
    )
    candidates = collect_board_candidates(hits)
    assert len(candidates) == 10
    assert len(select_board_verification_candidates(candidates)) == 8


def test_ninth_duplicate_does_not_exceed_verification_cap() -> None:
    hits = tuple(
        [
            *(
                BoardSearchHitV2(1, "brave", index, f"https://boards.greenhouse.io/board-{index}")
                for index in range(1, 9)
            ),
            BoardSearchHitV2(2, "tavily", 1, "https://boards.greenhouse.io/board-8"),
        ]
    )
    candidates = collect_board_candidates(hits)
    assert len(candidates) == 8
    assert len(select_board_verification_candidates(candidates)) == 8
