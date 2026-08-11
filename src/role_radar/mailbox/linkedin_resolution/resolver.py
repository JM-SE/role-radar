"""Pure-ish bounded redirect state machine for LinkedIn HEAD resolution."""

from __future__ import annotations

import asyncio

from role_radar.mailbox.linkedin_resolution.contracts import (
    TERMINAL_CODES,
    AuthenticatedLinkedInProposal,
    HeadResolutionReport,
)
from role_radar.mailbox.linkedin_resolution.dns import (
    DNSResolutionError,
    DNSResolver,
    EgressGuard,
    pin_public_address,
)
from role_radar.mailbox.linkedin_resolution.policy import (
    MAX_REDIRECTS,
    MAX_REQUESTS,
    REDIRECT_STATUSES,
    ATSTarget,
    ResolutionPolicyError,
    classify_location,
    validate_linkedin_url,
)
from role_radar.mailbox.linkedin_resolution.transport import HeadTransport, HeadTransportError


class LinkedInHeadResolver:
    def __init__(
        self,
        transport: HeadTransport,
        dns: DNSResolver,
        egress: EgressGuard,
    ) -> None:
        self._transport = transport
        self._dns = dns
        self._egress = egress

    async def resolve(self, proposal: AuthenticatedLinkedInProposal) -> HeadResolutionReport:
        if proposal.parser_name != "linkedin" or proposal.auth_evidence != "pass":
            return _failure("parser_mismatch")
        if proposal.template_code == "drift":
            return _failure("template_drift")
        try:
            current = validate_linkedin_url(proposal.original_url_transient)
        except ResolutionPolicyError as exc:
            return _failure(exc.code)
        request_count = 0
        deadline = asyncio.get_running_loop().time() + 5.0
        while request_count < MAX_REQUESTS:
            try:
                address = await pin_public_address(
                    current.host,
                    self._dns,
                    self._egress,
                    deadline=deadline,
                )
                response = await self._transport.head(
                    current.url,
                    host=current.host,
                    address=address,
                    deadline=deadline,
                )
            except (DNSResolutionError, HeadTransportError) as exc:
                return _failure(exc.code, request_count)
            except Exception:
                return _failure("internal", request_count)
            request_count += 1
            if response.status_code == 429:
                return _failure("rate_limited", request_count)
            if response.status_code not in REDIRECT_STATUSES:
                return _failure("unsupported_status", request_count)
            if response.location is None:
                return _failure("location_missing", request_count, request_count)
            try:
                target = classify_location(current.url, response.location)
            except ResolutionPolicyError as exc:
                return _failure(exc.code, request_count, request_count)
            if isinstance(target, ATSTarget):
                return _success(request_count, request_count, target)
            current = target
        return _failure("request_limit", request_count, MAX_REDIRECTS)


def _success(request_count: int, redirect_count: int, target: ATSTarget) -> HeadResolutionReport:
    return HeadResolutionReport("intake", request_count, redirect_count, target.final_ats, None)


def _failure(
    code: str,
    request_count: int = 0,
    redirect_count: int = 0,
) -> HeadResolutionReport:
    safe_code = code if code in TERMINAL_CODES else "internal"
    return HeadResolutionReport("review", request_count, redirect_count, None, safe_code)
