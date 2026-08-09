"""Pure activation gates and external-auth policy checks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from role_radar.acquisition.jobicy_terms_evidence import (
    BUNDLE_FORMAT_VERSION,
    POLICY_VERSION,
    RSS_URL,
    TERMS_URL,
    JobicyTermsEvidence,
)
from role_radar.free_sources.terms import JobicyTermsAcceptance

XOAUTH2_MIN_FRESHNESS = timedelta(minutes=5)
_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


class ActivationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def build_jobicy_acceptance(
    evidence: JobicyTermsEvidence,
    *,
    terms_sha256: str,
    reviewed_at: datetime,
    fair_use_ack: bool,
    preserve_destination_ack: bool,
    no_redistribution_ack: bool,
    now: datetime,
) -> JobicyTermsAcceptance:
    if evidence.terms_sha256 != terms_sha256:
        raise ActivationError("terms_manifest_digest_mismatch")
    if (
        evidence.policy_version != POLICY_VERSION
        or evidence.bundle_format_version != BUNDLE_FORMAT_VERSION
    ):
        raise ActivationError("terms_policy_mismatch")
    _validate_review_window(reviewed_at, now)
    if any(page.retrieved_at > reviewed_at.astimezone(UTC) for page in evidence.pages):
        raise ActivationError("terms_review_future")
    if not fair_use_ack:
        raise ActivationError("terms_ack_missing")
    if not preserve_destination_ack:
        raise ActivationError("terms_ack_missing")
    if not no_redistribution_ack:
        raise ActivationError("terms_ack_missing")
    if tuple(page.url for page in evidence.pages) != (TERMS_URL, RSS_URL):
        raise ActivationError("terms_url_disallowed")
    return JobicyTermsAcceptance(
        TERMS_URL,
        reviewed_at.astimezone(UTC),
        POLICY_VERSION,
        fair_use_ack,
        preserve_destination_ack,
        no_redistribution_ack,
        evidence.terms_sha256,
        BUNDLE_FORMAT_VERSION,
    )


def validate_jobicy_activation(
    evidence: JobicyTermsEvidence | None,
    *,
    terms_sha256: str | None,
    reviewed_at: datetime | None,
    fair_use_ack: bool,
    preserve_destination_ack: bool,
    no_redistribution_ack: bool,
    now: datetime,
) -> JobicyTermsAcceptance:
    if evidence is None or terms_sha256 is None or reviewed_at is None:
        raise ActivationError("terms_missing")
    return build_jobicy_acceptance(
        evidence,
        terms_sha256=terms_sha256,
        reviewed_at=reviewed_at,
        fair_use_ack=fair_use_ack,
        preserve_destination_ack=preserve_destination_ack,
        no_redistribution_ack=no_redistribution_ack,
        now=now,
    )


def _validate_review_window(reviewed_at: datetime, now: datetime) -> None:
    if reviewed_at.tzinfo is None or reviewed_at.utcoffset() != timedelta(0):
        raise ActivationError("terms_review_invalid")
    age = now.astimezone(UTC) - reviewed_at.astimezone(UTC)
    if age < timedelta(0):
        raise ActivationError("terms_review_future")
    if age > timedelta(days=30):
        raise ActivationError("terms_review_stale")


def parse_xoauth_expiry(metadata: bytes | str, *, now: datetime) -> datetime:
    try:
        raw = json.loads(metadata.decode("utf-8") if isinstance(metadata, bytes) else metadata)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
        raise ActivationError("oauth_expiry_invalid") from exc
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema_version", "expires_at"}
        or raw["schema_version"] != 1
    ):
        raise ActivationError("oauth_expiry_invalid")
    value = raw["expires_at"]
    if not isinstance(value, str) or _RFC3339_Z.fullmatch(value) is None:
        raise ActivationError("oauth_expiry_invalid")
    try:
        expiry = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ActivationError("oauth_expiry_invalid") from exc
    if expiry.tzinfo is None or expiry.utcoffset() != timedelta(0):
        raise ActivationError("oauth_expiry_invalid")
    if expiry.astimezone(UTC) - now.astimezone(UTC) < XOAUTH2_MIN_FRESHNESS:
        raise ActivationError("oauth_not_fresh")
    return expiry.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class AppPasswordPolicy:
    two_factor_ack: bool
    mailbox_scope_ack: bool
    revocation_ack: bool
    dedicated_account_ack: bool = False

    def validate(self) -> str | None:
        if not self.two_factor_ack:
            raise ActivationError("app_password_2fa_unacknowledged")
        if not self.mailbox_scope_ack:
            raise ActivationError("app_password_scope_unacknowledged")
        if not self.revocation_ack:
            raise ActivationError("app_password_revocation_unacknowledged")
        return None if self.dedicated_account_ack else "dedicated_account_recommended"


def require_live_smoke_ack(*, ack_live: bool, confirmation: str | None, capability: str) -> None:
    if not ack_live or confirmation != f"LIVE {capability.upper()}":
        raise ActivationError("live_ack_required")
