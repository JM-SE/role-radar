"""Shared conservative link-output helpers for mailbox parsers."""

from urllib.parse import urlsplit

from role_radar.discovery.url_classifier import classify_url
from role_radar.mailbox.contracts import (
    BoundedMailboxMessage,
    LinkLead,
    ParseResult,
    ReviewProposal,
)
from role_radar.mailbox.parser_registry import trusted_sender


def parse_links(
    message: BoundedMailboxMessage,
    *,
    parser_name: str,
    parser_version: str,
    trusted_domains: frozenset[str],
    template_marker: str,
) -> ParseResult:
    text = f"{message.subject}\n{message.text}".lower()
    trusted = trusted_sender(message, trusted_domains)
    if template_marker not in text:
        return ParseResult(
            parser_name,
            parser_version,
            (
                ReviewProposal(
                    "template_drift",
                    "template_drift",
                    parser_name=parser_name,
                    parser_version=parser_version,
                ),
            ),
            template_code="drift",
            terminal_code="template_drift",
        )
    if not trusted:
        reason = "auth_required" if message.auth_evidence != "pass" else "sender_not_allowlisted"
        return ParseResult(
            parser_name,
            parser_version,
            (
                ReviewProposal(
                    "quarantine",
                    reason,
                    parser_name=parser_name,
                    parser_version=parser_version,
                ),
            ),
            template_code="recognized",
            terminal_code="review",
        )
    outputs: list[LinkLead | ReviewProposal] = []
    for url in message.urls:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https" or parsed.username or parsed.fragment:
            outputs.append(
                ReviewProposal("link", "ambiguous_url", url, parser_name, parser_version)
            )
            continue
        candidate = classify_url(url)
        if candidate.__class__.__name__ in {
            "GreenhouseOfficialCandidate",
            "LeverOfficialCandidate",
        }:
            outputs.append(LinkLead(url, "ats_direct", parser_name, parser_version))
        else:
            outputs.append(
                ReviewProposal("link", "email_intake_only", url, parser_name, parser_version)
            )
    if not outputs:
        outputs.append(
            ReviewProposal(
                "message",
                "no_link",
                parser_name=parser_name,
                parser_version=parser_version,
            )
        )
    return ParseResult(parser_name, parser_version, tuple(outputs), template_code="recognized")
