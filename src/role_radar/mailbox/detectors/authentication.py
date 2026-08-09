"""Conservative authentication checks used by auto-v1."""

from role_radar.mailbox.detectors.contracts import AuthEvidence


def dmarc_aligned(evidence: AuthEvidence, *, identity_domain: str) -> bool:
    return (
        not evidence.hostile
        and evidence.authserv_id == "mx.google.com"
        and evidence.dmarc_pass
        and _exact_or_subdomain(evidence.header_from_domain or "", identity_domain)
    )


def dkim_with_list_id(evidence: AuthEvidence, *, dkim_domain: str, expected_list_id: str) -> bool:
    return (
        not evidence.hostile
        and evidence.authserv_id == "mx.google.com"
        and dkim_domain in evidence.dkim_domains
        and evidence.list_id == expected_list_id
    )


def _exact_or_subdomain(value: str, expected: str) -> bool:
    return value == expected or value.endswith("." + expected)
