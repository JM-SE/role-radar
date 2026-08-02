"""Pure deterministic candidate selector."""

from collections.abc import Iterable

from .contracts import DeepEvaluationCandidateV1, DeepSelectionV1
from .policy import DeepEvaluationPolicyV1


def select_candidates(
    candidates: Iterable[DeepEvaluationCandidateV1],
    policy: DeepEvaluationPolicyV1 | None = None,
) -> tuple[DeepSelectionV1, ...]:
    policy = policy or DeepEvaluationPolicyV1()
    eligible: list[tuple[DeepEvaluationCandidateV1, str]] = []
    for candidate in candidates:
        if not candidate.eligible or candidate.blockers:
            continue
        if candidate.preliminary_score >= policy.high_score_min:
            eligible.append((candidate, "high_score"))
        elif (
            policy.ambiguous_score_min <= candidate.preliminary_score <= policy.ambiguous_score_max
            and candidate.resolvable_ambiguities
        ):
            eligible.append((candidate, "ambiguous_band"))
    eligible.sort(
        key=lambda item: (
            -item[0].preliminary_score,
            -item[0].first_seen_at.timestamp(),
            item[0].job_id,
        )
    )
    return tuple(
        DeepSelectionV1(candidate, index, reason)  # type: ignore[arg-type]
        for index, (candidate, reason) in enumerate(eligible[: policy.max_per_run], 1)
    )


def selection_reason(
    score: int, resolvable: bool, policy: DeepEvaluationPolicyV1 | None = None
) -> str:
    policy = policy or DeepEvaluationPolicyV1()
    if score >= policy.high_score_min:
        return "high_score"
    if policy.ambiguous_score_min <= score <= policy.ambiguous_score_max and resolvable:
        return "ambiguous_band"
    return "not_selected"
