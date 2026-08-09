"""Wellfound/AngelList alert parser."""

from role_radar.mailbox.contracts import BoundedMailboxMessage, ParseResult
from role_radar.mailbox.parsers.common import parse_links


def parse(message: BoundedMailboxMessage) -> ParseResult:
    return parse_links(
        message,
        parser_name="wellfound",
        parser_version="wellfound-alert-v1",
        trusted_domains=frozenset({"wellfound.com", "angel.co"}),
        template_marker="wellfound",
    )
