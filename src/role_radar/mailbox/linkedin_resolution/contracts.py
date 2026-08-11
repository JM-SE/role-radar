"""Transient contracts for the F9.1 LinkedIn HEAD resolver."""

from __future__ import annotations

from dataclasses import dataclass, field

TERMINAL_CODES = frozenset(
    {
        "live_ack_required", "source_not_found", "source_must_be_disabled",
        "source_type_invalid", "no_authenticated_linkedin_proposal", "parser_mismatch",
        "template_drift", "allowlist_rejected", "url_invalid", "location_missing",
        "location_invalid", "location_limit", "unsupported_status", "request_limit",
        "timeout_connect", "timeout_operation", "dns_failure", "dns_private_address",
        "dns_rebinding", "tls_failure", "headers_oversize", "response_protocol",
        "rate_limited", "circuit_open", "ats_unsupported", "ats_invalid",
        "ats_posting_missing", "exact_posting_mismatch", "concurrent_claim",
        "retry_exhausted", "persistence_disabled", "config", "internal",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedLinkedInProposal:
    source_id: str
    receipt_id: str
    proposal_id: str
    parser_name: str
    parser_version: str
    template_code: str
    auth_evidence: str
    original_url_transient: str = field(repr=False)
    source_revision: int = 1
    operation_id: str = "f9.1-report-only"


@dataclass(frozen=True, slots=True)
class FinalATS:
    provider: str
    host: str
    external_id: str
    posting_exact: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "host": self.host,
            "external_id": self.external_id,
            "posting_exact": self.posting_exact,
        }


@dataclass(frozen=True, slots=True)
class HeadResponse:
    status_code: int
    location: str | None = None


@dataclass(frozen=True, slots=True)
class HeadResolutionReport:
    result: str
    request_count: int
    redirect_count: int
    final_ats: FinalATS | None
    terminal_code: str | None
    source_state: str = "disabled"
    proposal_state: str = "authenticated_linkedin"

    def as_dict(self) -> dict[str, object]:
        request_count = min(max(self.request_count, 0), 3)
        redirect_count = min(max(self.redirect_count, 0), 2)
        terminal_code = self.terminal_code if self.terminal_code in TERMINAL_CODES else "internal"
        return {
            "schema_version": "linkedin-head-resolution-v1",
            "policy_version": "linkedin-head-resolution-v1",
            "mode": "report_only",
            "source_state": self.source_state,
            "proposal_state": self.proposal_state,
            "result": self.result,
            "request_count": request_count,
            "redirect_count": redirect_count,
            "final_ats": self.final_ats.as_dict() if self.final_ats else None,
            "terminal_code": terminal_code,
        }
