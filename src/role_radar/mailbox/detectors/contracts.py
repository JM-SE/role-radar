"""Sanitized evidence contracts for parser auto-selection."""

from dataclasses import dataclass

from role_radar.mailbox.contracts import BoundedMailboxMessage


@dataclass(frozen=True, slots=True)
class AuthEvidence:
    authserv_id: str | None
    dmarc_pass: bool
    dmarc_aligned: bool
    dkim_domains: tuple[str, ...]
    list_id: str | None
    header_from_domain: str | None = None
    hostile: bool = False


@dataclass(frozen=True, slots=True)
class AutoMatch:
    parser_name: str
    detector_version: str
    fingerprint_version: str


def auth_evidence(message: BoundedMailboxMessage) -> AuthEvidence:
    return AuthEvidence(
        message.authserv_id,
        message.dmarc_result == "pass",
        message.dmarc_result == "pass" and message.header_from_domain is not None,
        message.dkim_domains,
        message.list_id,
        message.header_from_domain,
        message.auth_ambiguous,
    )
