from role_radar.mailbox.contracts import BoundedMailboxMessage
from role_radar.mailbox.detectors._common import authenticated_identity
from role_radar.mailbox.detectors.contracts import AutoMatch

DETECTOR_VERSION = "wellfound-detector-v1"
FINGERPRINT_VERSION = "wellfound-alert-v1"


def match(message: BoundedMailboxMessage) -> AutoMatch | None:
    text = f"{getattr(message, 'subject', '')} {getattr(message, 'text', '')}".lower()
    if (
        getattr(message, "sender_domain", None) in {"wellfound.com", "angel.co"}
        and "wellfound" in text
        and authenticated_identity(message, getattr(message, "sender_domain", ""))
    ):
        return AutoMatch("wellfound", DETECTOR_VERSION, FINGERPRINT_VERSION)
    return None


detect = match
