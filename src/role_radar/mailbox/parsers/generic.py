"""Generic trusted newsletter parser, review-only by design."""

from role_radar.mailbox.contracts import BoundedMailboxMessage, ParseResult, ReviewProposal
from role_radar.mailbox.parser_registry import trusted_sender


def parse(message: BoundedMailboxMessage) -> ParseResult:
    trusted = trusted_sender(message, frozenset({message.sender_domain or ""}))
    reason = "newsletter_link_review" if trusted else "auth_or_sender_review"
    outputs = tuple(
        ReviewProposal("link", reason, url, "generic", "generic-newsletter-v1")
        for url in message.urls
    ) or (
        ReviewProposal(
            "message", reason, parser_name="generic", parser_version="generic-newsletter-v1"
        ),
    )
    return ParseResult("generic", "generic-newsletter-v1", outputs, template_code="generic")
