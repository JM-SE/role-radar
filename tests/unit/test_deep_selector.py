from datetime import UTC, datetime

from role_radar.deep_evaluation.contracts import (
    DeepEvaluationCandidateV1,
    EvidenceReferenceV1,
    ResolvableAmbiguityV1,
)
from role_radar.deep_evaluation.selector import select_candidates


def candidate(
    score: int, *, resolvable: bool = False, blockers: bool = False, job_id: str = "j"
) -> DeepEvaluationCandidateV1:
    ambiguities = (
        (
            ResolvableAmbiguityV1(
                "remote_policy_unknown",
                "remote_policy",
                "Which arrangement?",
                (EvidenceReferenceV1("extraction", "remote_policy[0].evidence", "remote"),),
            ),
        )
        if resolvable
        else ()
    )
    return DeepEvaluationCandidateV1(
        job_id,
        f"s-{job_id}",
        "p",
        "e",
        "T",
        "C",
        None,
        datetime(2026, 1, 1, tzinfo=UTC),
        score,
        not blockers,
        ({"code": "b"},) if blockers else (),
        (),
        (),
        ambiguities,
        "ambiguity-resolution-v1",
    )


def test_boundaries_require_evidence_in_ambiguous_band() -> None:
    selected = select_candidates(
        [candidate(54), candidate(55), candidate(74, resolvable=True), candidate(74), candidate(75)]
    )
    assert [item.candidate.preliminary_score for item in selected] == [75, 74]


def test_blockers_and_top_ten_are_deterministic() -> None:
    rows = [candidate(100, job_id=f"{i:02d}") for i in range(12)] + [
        candidate(100, blockers=True, job_id="blocked")
    ]
    selected = select_candidates(rows)
    assert len(selected) == 10
    assert "blocked" not in {item.candidate.job_id for item in selected}
    assert [item.rank for item in selected] == list(range(1, 11))
