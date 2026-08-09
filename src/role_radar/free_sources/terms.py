"""Code-owned Jobicy terms/fair-use gate."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

JOBICY_TERMS_POLICY_VERSION = "jobicy-terms-v1"
JOBICY_TERMS_MAX_AGE = timedelta(days=30)


@dataclass(frozen=True, slots=True)
class JobicyTermsAcceptance:
    terms_url: str
    reviewed_at: datetime
    policy_version: str
    fair_use_ack: bool
    preserve_destination_ack: bool
    no_redistribution_ack: bool


def validate_jobicy_terms(
    acceptance: JobicyTermsAcceptance | None, *, now: datetime
) -> str | None:
    if acceptance is None:
        return "terms_missing"
    if not acceptance.terms_url or not acceptance.terms_url.startswith("https://"):
        return "terms_missing"
    if acceptance.policy_version != JOBICY_TERMS_POLICY_VERSION:
        return "terms_changed"
    reviewed = acceptance.reviewed_at
    if reviewed.tzinfo is None or reviewed.utcoffset() is None:
        return "terms_stale"
    age = now.astimezone(UTC) - reviewed.astimezone(UTC)
    if age < timedelta(0) or age > JOBICY_TERMS_MAX_AGE:
        return "terms_stale"
    if not (
        acceptance.fair_use_ack
        and acceptance.preserve_destination_ack
        and acceptance.no_redistribution_ack
    ):
        return "terms_missing"
    return None
