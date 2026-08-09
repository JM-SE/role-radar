from role_radar.mailbox.contracts import BoundedMailboxMessage


def authenticated_identity(message: BoundedMailboxMessage, domain: str) -> bool:
    if message.auth_ambiguous or message.authserv_id != "mx.google.com":
        return False
    # No vendor in the current fixture set has a reliable List-ID.  Keep the
    # DKIM branch disabled until an exact, reviewed List-ID is added.
    return message.dmarc_result == "pass" and message.header_from_domain == domain
