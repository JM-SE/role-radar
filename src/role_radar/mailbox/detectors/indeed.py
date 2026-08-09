from role_radar.mailbox.contracts import BoundedMailboxMessage
from role_radar.mailbox.detectors._common import authenticated_identity
from role_radar.mailbox.detectors.contracts import AutoMatch

DETECTOR_VERSION = "indeed-detector-v1"
FINGERPRINT_VERSION = "indeed-alert-v1"


def match(message: BoundedMailboxMessage) -> AutoMatch | None:
    text = f"{getattr(message, 'subject', '')} {getattr(message, 'text', '')}".lower()
    if (
        getattr(message, "sender_domain", None) == "indeed.com"
        and "indeed" in text
        and authenticated_identity(message, "indeed.com")
    ):
        return AutoMatch("indeed", DETECTOR_VERSION, FINGERPRINT_VERSION)
    return None


detect = match
