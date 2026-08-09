"""LinkedIn Job Alerts parser: links remain intake/review, never fetched."""

from role_radar.mailbox.contracts import BoundedMailboxMessage, ParseResult
from role_radar.mailbox.parsers.common import parse_links


def parse(message: BoundedMailboxMessage) -> ParseResult:
    return parse_links(
        message,
        parser_name="linkedin",
        parser_version="linkedin-job-alert-v1",
        trusted_domains=frozenset({"linkedin.com"}),
        template_marker="job alert",
    )
