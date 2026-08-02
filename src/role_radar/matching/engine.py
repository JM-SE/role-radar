"""Aggregation-only matching engine: no ORM, clock, network, or randomness."""

from __future__ import annotations

import hashlib
import json

from role_radar.domain.profile import CandidateProfileV1
from role_radar.matching.contracts import Ambiguity, JobFacts, MatchResult
from role_radar.matching.hard_filters import evaluate_hard_filters
from role_radar.matching.policy import POLICY_VERSION, SCORING_VERSION, ScoringPolicyV1
from role_radar.matching.signals import calculate_signals


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def score_job(
    profile: CandidateProfileV1,
    facts: JobFacts,
    *,
    job_id: str,
    profile_id: str,
    extraction_id: str | None = None,
    policy: ScoringPolicyV1 | None = None,
    adaptation_ambiguities: tuple[Ambiguity, ...] = (),
) -> MatchResult:
    chosen_policy = policy or ScoringPolicyV1()
    input_hash = hashlib.sha256(
        _canonical_json(
            {"profile": profile.model_dump(mode="json"), "facts": facts.canonical_dict()}
        ).encode()
    ).hexdigest()
    operation_key = _canonical_json(
        {
            "job_id": job_id,
            "profile_id": profile_id,
            "extraction_id": extraction_id,
            "input_hash": input_hash,
            "scoring_version": SCORING_VERSION,
            "policy_version": POLICY_VERSION,
        }
    )
    blockers = evaluate_hard_filters(profile, facts)
    signals, signal_ambiguities = calculate_signals(profile, facts, chosen_policy)
    ambiguities = tuple(
        sorted(
            {
                (item.code, item.field, item.provenance, item.detail): item
                for item in (*adaptation_ambiguities, *signal_ambiguities)
            }.values(),
            key=lambda item: (item.code, item.field, item.detail),
        )
    )
    score = sum(signal.points for signal in signals)
    if score < 0 or score > 100 or sum(signal.max_points for signal in signals) != 100:
        raise ValueError("matching score accounting invariant failed")
    return MatchResult(
        scoring_version=SCORING_VERSION,
        policy_version=POLICY_VERSION,
        preliminary_score=score,
        eligible=not blockers,
        signals=signals,
        blockers=tuple(blockers),
        ambiguities=ambiguities,
        input_hash=input_hash,
        operation_key=operation_key,
        extraction_id=extraction_id,
    )
