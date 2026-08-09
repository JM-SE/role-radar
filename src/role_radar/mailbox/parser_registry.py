"""Static parser registry and conservative trust policy."""

from collections.abc import Callable

from role_radar.mailbox.contracts import (
    BoundedMailboxMessage,
    ParseResult,
    TerminalRejection,
)
from role_radar.mailbox.detectors.registry import REGISTRY_VERSION
from role_radar.mailbox.detectors.registry import select as select_auto

Parser = Callable[[BoundedMailboxMessage], ParseResult]


def trusted_sender(message: BoundedMailboxMessage, domains: frozenset[str]) -> bool:
    sender = message.sender_domain or ""
    list_id = message.list_id or ""
    return any(
        value == candidate or value.endswith("." + candidate)
        for value in (sender, list_id)
        for candidate in domains
    ) and message.auth_evidence == "pass"


class MailboxParserRegistry:
    """No plugins and no parser name selected by message text."""

    def __init__(self, parsers: dict[str, Parser]) -> None:
        self._parsers = dict(parsers)

    def parse(self, profile: str, message: BoundedMailboxMessage) -> ParseResult:
        if profile == "auto":
            selected, match = select_auto(message)
            if match is None:
                code = "quarantine" if selected == "ambiguous" else "review"
                return ParseResult(
                    selected,
                    REGISTRY_VERSION,
                    (TerminalRejection(code, selected, REGISTRY_VERSION),),
                    template_code=REGISTRY_VERSION,
                    terminal_code=code,
                )
            parser = self._parsers.get(selected)
            if parser is None:
                return ParseResult("unknown", REGISTRY_VERSION, terminal_code="review")
            parsed = parser(message)
            return ParseResult(
                parsed.parser_name,
                parsed.schema_version,
                parsed.outputs,
                f"{REGISTRY_VERSION}:{match.detector_version}:{match.fingerprint_version}",
                parsed.terminal_code,
            )
        parser = self._parsers.get(profile)
        if parser is None:
            return ParseResult(
                "unknown",
                "1",
                (TerminalRejection("unsupported", "unknown", "1"),),
                terminal_code="unsupported",
            )
        return parser(message)


def default_registry() -> MailboxParserRegistry:
    from role_radar.mailbox.parsers.generic import parse as generic
    from role_radar.mailbox.parsers.google_alerts import parse as google_alerts
    from role_radar.mailbox.parsers.indeed import parse as indeed
    from role_radar.mailbox.parsers.linkedin import parse as linkedin
    from role_radar.mailbox.parsers.wellfound import parse as wellfound

    return MailboxParserRegistry(
        {
            "linkedin": linkedin,
            "indeed": indeed,
            "google_alerts": google_alerts,
            "wellfound": wellfound,
            "generic": generic,
            "unknown": lambda _message: ParseResult(
                "unknown",
                "1",
                (TerminalRejection("unknown", "unknown", "1"),),
                terminal_code="review",
            ),
        }
    )
