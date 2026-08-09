from role_radar.mailbox.contracts import BoundedMailboxMessage
from role_radar.mailbox.detectors._common import authenticated_identity
from role_radar.mailbox.detectors.contracts import AutoMatch

DETECTOR_VERSION = "linkedin-detector-v1"
FINGERPRINT_VERSION = "linkedin-job-alert-v1"


def match(message: BoundedMailboxMessage) -> AutoMatch | None:
    value = getattr(message, "sender_domain", None)
    text = f"{getattr(message, 'subject', '')} {getattr(message, 'text', '')}".lower()
    if value == "linkedin.com" and "job alert" in text and authenticated_identity(message, value):
        return AutoMatch("linkedin", DETECTOR_VERSION, FINGERPRINT_VERSION)
    return None


detect = match
