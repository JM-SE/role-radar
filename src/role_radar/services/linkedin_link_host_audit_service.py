"""Report-only orchestration for the F9.0 LinkedIn host audit."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from role_radar.mailbox.contracts import MailboxErrorCode, MailboxProvider
from role_radar.mailbox.link_host_audit import (
    SCHEMA_VERSION,
    TERMINAL_CODES,
    LinkHostAudit,
    audit_link_hosts,
)
from role_radar.mailbox.mime_parser import parse_rfc822
from role_radar.mailbox.parser_registry import MailboxParserRegistry, default_registry

LOOKBACK_DAYS = 14
AUDIT_LIMIT = 1


@dataclass(frozen=True, slots=True)
class LinkedInLinkHostAuditReport:
    validated: bool
    selected: int
    fetched: int
    parser: str
    template: str
    total_url_count: int
    distinct_host_count: int
    host_summaries: tuple[dict[str, object], ...]
    terminal_code: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "policy_version": SCHEMA_VERSION,
            "validated": self.validated,
            "selected": self.selected,
            "fetched": self.fetched,
            "parser": self.parser,
            "template": self.template,
            "total_url_count": self.total_url_count,
            "distinct_host_count": self.distinct_host_count,
            "host_summaries": list(self.host_summaries),
            "terminal_code": self.terminal_code,
        }


class LinkedInLinkHostAuditService:
    """Run one bounded audit without ORM, persistence, or link-host I/O."""

    def __init__(
        self,
        provider: MailboxProvider,
        *,
        parser_profile: str = "auto",
        parser_registry: MailboxParserRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._provider = provider
        self._parser_profile = parser_profile
        self._registry = parser_registry or default_registry()
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(self) -> LinkedInLinkHostAuditReport:
        try:
            return await self._run()
        except Exception as exc:
            return _failure(_error_code(exc))
        finally:
            with suppress(Exception):
                await self._provider.close()

    async def _run(self) -> LinkedInLinkHostAuditReport:
        preflight = await self._provider.preflight()
        if not preflight.readonly:
            return _failure("protocol")
        since = _utc(self._clock()) - timedelta(days=LOOKBACK_DAYS)
        refs = await self._provider.list_uids(
            uidvalidity=preflight.uidvalidity,
            since=since,
            limit=AUDIT_LIMIT,
        )
        if len(refs) > AUDIT_LIMIT:
            return _failure("message_limit")
        if not refs:
            return _failure("empty")
        selected = 1
        try:
            raw = await self._provider.fetch(refs[0])
        except Exception as exc:
            return _failure(_error_code(exc), selected=selected)
        fetched = 1
        try:
            message = parse_rfc822(raw)
            parsed = self._registry.parse(self._parser_profile, message)
        except Exception as exc:
            return _failure(_parser_error_code(exc), selected=selected, fetched=fetched)
        if parsed.parser_name != "linkedin":
            return _failure("parser_mismatch", selected=selected, fetched=fetched)
        if parsed.terminal_code is not None:
            return _failure(
                _terminal_code(parsed.terminal_code), selected=selected, fetched=fetched
            )
        audit = audit_link_hosts(message.urls)
        return _from_audit(selected, fetched, audit)


def _from_audit(
    selected: int, fetched: int, audit: LinkHostAudit
) -> LinkedInLinkHostAuditReport:
    return LinkedInLinkHostAuditReport(
        audit.validated and audit.terminal_code is None,
        selected,
        fetched,
        "linkedin",
        "recognized",
        audit.total_url_count,
        audit.distinct_host_count,
        tuple(item.as_dict() for item in audit.host_summaries),
        audit.terminal_code,
    )


def _failure(
    code: str,
    *,
    selected: int = 0,
    fetched: int = 0,
) -> LinkedInLinkHostAuditReport:
    return LinkedInLinkHostAuditReport(
        False,
        selected,
        fetched,
        "unknown",
        "unknown",
        0,
        0,
        (),
        _terminal_code(code),
    )


def _error_code(error: BaseException) -> str:
    value = getattr(error, "code", None)
    return value if isinstance(value, str) else MailboxErrorCode.PROTOCOL.value


def _parser_error_code(error: BaseException) -> str:
    value = getattr(error, "code", None)
    return value if isinstance(value, str) else MailboxErrorCode.MALFORMED.value


def _terminal_code(value: str | None) -> str:
    return value if value in TERMINAL_CODES else "protocol"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
