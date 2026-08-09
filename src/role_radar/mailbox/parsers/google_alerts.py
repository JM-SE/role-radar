"""Google Alerts parser; alert text is never reused as a search query."""

from role_radar.mailbox.contracts import BoundedMailboxMessage, ParseResult
from role_radar.mailbox.parsers.common import parse_links


def parse(message: BoundedMailboxMessage) -> ParseResult:
    return parse_links(
        message,
        parser_name="google_alerts",
        parser_version="google-alerts-v1",
        trusted_domains=frozenset({"google.com", "googlealerts-noreply.com"}),
        template_marker="google alerts",
    )
