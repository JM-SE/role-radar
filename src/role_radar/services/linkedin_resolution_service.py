"""Transient Gmail intake orchestration for F9.1 report-only resolution."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from role_radar.mailbox.contracts import MailboxProvider, ReviewProposal
from role_radar.mailbox.linkedin_resolution.contracts import (
    TERMINAL_CODES,
    AuthenticatedLinkedInProposal,
    HeadResolutionReport,
)
from role_radar.mailbox.linkedin_resolution.resolver import LinkedInHeadResolver
from role_radar.mailbox.mime_parser import parse_rfc822
from role_radar.mailbox.parser_registry import MailboxParserRegistry, default_registry

LOOKBACK_DAYS = 14
MESSAGE_LIMIT = 1


class LinkedInResolutionMailboxService:
    """Read one authenticated alert, then resolve one transient proposal."""

    def __init__(
        self,
        provider: MailboxProvider,
        resolver: LinkedInHeadResolver,
        *,
        parser_profile: str = "auto",
        parser_registry: MailboxParserRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
        source_id: str = "transient-email-role-radar",
        source_revision: int = 1,
    ) -> None:
        self._provider = provider
        self._resolver = resolver
        self._parser_profile = parser_profile
        self._registry = parser_registry or default_registry()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source_id = source_id
        self._source_revision = source_revision

    async def run(self) -> HeadResolutionReport:
        try:
            preflight = await self._provider.preflight()
            if not preflight.readonly:
                return _failure("internal")
            refs = await self._provider.list_uids(
                uidvalidity=preflight.uidvalidity,
                since=_utc(self._clock()) - timedelta(days=LOOKBACK_DAYS),
                limit=MESSAGE_LIMIT,
            )
            if len(refs) != 1:
                return _failure("no_authenticated_linkedin_proposal")
            raw = await self._provider.fetch(refs[0])
            message = parse_rfc822(raw)
            parsed = self._registry.parse(self._parser_profile, message)
            if parsed.parser_name != "linkedin":
                return _failure("parser_mismatch")
            if parsed.template_code == "drift":
                return _failure("template_drift")
            if parsed.terminal_code is not None or message.auth_evidence != "pass":
                return _failure("no_authenticated_linkedin_proposal")
            proposal = next(
                (
                    output
                    for output in parsed.outputs
                    if isinstance(output, ReviewProposal) and output.url is not None
                ),
                None,
            )
            if proposal is None or proposal.url is None:
                return _failure("no_authenticated_linkedin_proposal")
            return await self._resolver.resolve(
                AuthenticatedLinkedInProposal(
                    source_id=self._source_id,
                    receipt_id="transient-mailbox-receipt",
                    proposal_id=str(refs[0].uid),
                    parser_name=parsed.parser_name,
                    parser_version=parsed.schema_version,
                    template_code="recognized",
                    auth_evidence=message.auth_evidence,
                    original_url_transient=proposal.url,
                    source_revision=self._source_revision,
                )
            )
        except Exception as exc:
            return _failure(getattr(exc, "code", "internal"))
        finally:
            with suppress(Exception):
                await self._provider.close()


def _failure(code: object) -> HeadResolutionReport:
    value = code if isinstance(code, str) else "internal"
    safe_code = value if value in TERMINAL_CODES else "internal"
    return HeadResolutionReport("review", 0, 0, None, safe_code)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
