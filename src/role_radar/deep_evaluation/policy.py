"""Versioned, pure F6 policy and score formula."""

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class DeepEvaluationPolicyV1:
    version: str = "deep-selector-v1"
    high_score_min: int = 75
    ambiguous_score_min: int = 55
    ambiguous_score_max: int = 74
    max_per_run: int = 10
    adjustment_limit: int = 15
    ambiguity_resolution_version: str = "ambiguity-resolution-v1"

    @property
    def policy_hash(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def calculate_adjustment(
    preliminary_score: int, fit_score: int, limit: int = 15
) -> tuple[int, int]:
    adjustment = clamp(fit_score - preliminary_score, -limit, limit)
    return adjustment, clamp(preliminary_score + adjustment, 0, 100)
