"""Digest selection rules. This module has no ORM or HTTP dependency."""

from dataclasses import dataclass, replace

from role_radar.notifications.contracts import DigestCandidate
from role_radar.notifications.url_policy import canonical_application_url

DIGEST_MAX_ITEMS = 5
MIN_FINAL_SCORE = 75


@dataclass(frozen=True, slots=True)
class SelectionResult:
    selected: tuple[DigestCandidate, ...]
    exclusions: tuple[tuple[str, str], ...]


def select_top_digest(
    candidates: list[DigestCandidate] | tuple[DigestCandidate, ...],
) -> SelectionResult:
    valid: list[DigestCandidate] = []
    exclusions: list[tuple[str, str]] = []
    for candidate in candidates:
        if candidate.final_score < MIN_FINAL_SCORE:
            exclusions.append((candidate.job_id, "final_score_below_threshold"))
        elif not canonical_application_url(candidate.application_url):
            exclusions.append((candidate.job_id, "invalid_application_url"))
        else:
            canonical = canonical_application_url(candidate.application_url)
            assert canonical is not None
            valid.append(replace(candidate, application_url=canonical))
    valid.sort(
        key=lambda item: (
            -item.final_score,
            -item.preliminary_score,
            -_timestamp(item),
            item.job_id,
        )
    )
    return SelectionResult(tuple(valid[:DIGEST_MAX_ITEMS]), tuple(exclusions))


def _timestamp(candidate: DigestCandidate) -> float:
    value = candidate.first_seen_at
    return value.timestamp() if hasattr(value, "timestamp") else 0.0
