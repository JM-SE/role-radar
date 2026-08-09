"""Code-owned Jobicy terms/fair-use gate."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

JOBICY_TERMS_POLICY_VERSION = "jobicy-terms-v1"
JOBICY_TERMS_MAX_AGE = timedelta(days=30)


@dataclass(frozen=True, slots=True, repr=False)
class JobicyTermsAcceptance:
    terms_url: str
    reviewed_at: datetime
    policy_version: str
    fair_use_ack: bool
    preserve_destination_ack: bool
    no_redistribution_ack: bool
    terms_sha256: str | None = None
    bundle_format_version: str = "jobicy-terms-bundle-v1"

    def __repr__(self) -> str:
        return "JobicyTermsAcceptance(<verified>)"


def validate_jobicy_terms(
    acceptance: JobicyTermsAcceptance | None, *, now: datetime
) -> str | None:
    if acceptance is None:
        return "terms_missing"
    if acceptance.terms_url != "https://jobicy.com/terms-and-conditions":
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
    if (
        acceptance.terms_sha256 is not None
        and re.fullmatch(r"[0-9a-f]{64}", acceptance.terms_sha256) is None
    ):
        return "terms_digest_invalid"
    if acceptance.bundle_format_version != "jobicy-terms-bundle-v1":
        return "terms_bundle_format_mismatch"
    return None
