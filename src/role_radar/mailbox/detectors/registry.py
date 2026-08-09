"""Fixed auto-v1 registry.  It never parses MIME or persists results."""

from role_radar.mailbox.contracts import BoundedMailboxMessage
from role_radar.mailbox.detectors.contracts import AutoMatch
from role_radar.mailbox.detectors.google_alerts import match as google_match
from role_radar.mailbox.detectors.indeed import match as indeed_match
from role_radar.mailbox.detectors.linkedin import match as linkedin_match
from role_radar.mailbox.detectors.wellfound import match as wellfound_match

REGISTRY_VERSION = "auto-v1"


def matches(message: BoundedMailboxMessage) -> tuple[AutoMatch, ...]:
    if message.auth_ambiguous:
        return ()
    return tuple(
        item
        for detector in (linkedin_match, indeed_match, google_match, wellfound_match)
        if (item := detector(message)) is not None
    )


def select(message: BoundedMailboxMessage) -> tuple[str, AutoMatch | None]:
    if message.auth_ambiguous:
        return "ambiguous", None
    found = matches(message)
    if len(found) == 1:
        return found[0].parser_name, found[0]
    return ("ambiguous" if len(found) > 1 else "unknown"), None
