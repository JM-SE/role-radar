"""Indeed alert parser."""

from role_radar.mailbox.contracts import BoundedMailboxMessage, ParseResult
from role_radar.mailbox.parsers.common import parse_links


def parse(message: BoundedMailboxMessage) -> ParseResult:
    return parse_links(
        message,
        parser_name="indeed",
        parser_version="indeed-alert-v1",
        trusted_domains=frozenset({"indeed.com"}),
        template_marker="indeed",
    )
