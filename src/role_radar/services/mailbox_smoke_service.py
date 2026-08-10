"""Bounded, report-only live smoke for one mailbox message."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from role_radar.mailbox.contracts import MailboxErrorCode, MailboxProvider, ParseResult
from role_radar.mailbox.mime_parser import parse_rfc822
from role_radar.mailbox.parser_registry import MailboxParserRegistry, default_registry

LOOKBACK_DAYS = 14
SMOKE_LIMIT = 1
MAX_TEMPLATE_CODE_LENGTH = 128
_SAFE_TEMPLATE_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_PARSER_NAMES = frozenset(
    {"linkedin", "indeed", "google_alerts", "wellfound", "generic", "unknown"}
)
_TERMINAL_CODES = frozenset(item.value for item in MailboxErrorCode) | frozenset(
    {"ambiguous", "auth_required", "quarantine", "review", "sender_not_allowlisted", "unknown"}
)


@dataclass(frozen=True, slots=True)
class MailboxSmokeResult:
    """Only bounded/sanitized fields may cross the CLI boundary."""

    validated: bool
    messages_selected: int
    messages_fetched: int
    parser_name: str
    template_code: str
    terminal_code: str | None
    output_count: int
    readonly: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "validated": self.validated,
            "messages_selected": self.messages_selected,
            "messages_fetched": self.messages_fetched,
            "parser_name": self.parser_name,
            "template_code": self.template_code,
            "terminal_code": self.terminal_code,
            "output_count": self.output_count,
            "readonly": self.readonly,
        }


class MailboxSmokeService:
    """Run one newest-message smoke without persistence or source mutation."""

    def __init__(
        self,
        provider: MailboxProvider,
        *,
        parser_profile: str,
        parser_registry: MailboxParserRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._provider = provider
        self._parser_profile = parser_profile
        self._registry = parser_registry or default_registry()
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(self) -> MailboxSmokeResult:
        selected = 0
        fetched = 0
        try:
            preflight = await self._provider.preflight()
            if not preflight.readonly:
                return _failure("protocol")
            since = _utc(self._clock()) - timedelta(days=LOOKBACK_DAYS)
            refs = await self._provider.list_uids(
                uidvalidity=preflight.uidvalidity,
                since=since,
                limit=SMOKE_LIMIT,
            )
            if len(refs) > SMOKE_LIMIT:
                return _failure("protocol")
            if not refs:
                return _empty_result()
            selected = 1
            raw = await self._provider.fetch(refs[0])
            fetched = 1
            try:
                message = parse_rfc822(raw)
                parsed = self._registry.parse(self._parser_profile, message)
            except Exception as exc:
                return _result_from_parser_error(
                    selected, fetched, getattr(exc, "code", "malformed")
                )
            return _result_from_parse(selected, fetched, parsed)
        except Exception as exc:
            return _failure(_error_code(exc))
        finally:
            await self._provider.close()


def _empty_result() -> MailboxSmokeResult:
    return MailboxSmokeResult(True, 0, 0, "unknown", "auto-v1", None, 0)


def _failure(code: str) -> MailboxSmokeResult:
    return MailboxSmokeResult(False, 0, 0, "unknown", "auto-v1", _safe_terminal_code(code), 0)


def _result_from_parse(selected: int, fetched: int, parsed: ParseResult) -> MailboxSmokeResult:
    terminal = _safe_terminal_code(parsed.terminal_code)
    return MailboxSmokeResult(
        True,
        selected,
        fetched,
        _safe_parser_name(parsed.parser_name),
        _safe_template_code(parsed.template_code),
        terminal,
        min(len(parsed.outputs), 100),
    )


def _result_from_parser_error(selected: int, fetched: int, code: object) -> MailboxSmokeResult:
    return MailboxSmokeResult(
        True,
        selected,
        fetched,
        "unknown",
        "auto-v1",
        _safe_terminal_code(str(code)),
        0,
    )


def _error_code(error: BaseException) -> str:
    value = getattr(error, "code", None)
    return value if isinstance(value, str) else MailboxErrorCode.PROTOCOL.value


def _safe_parser_name(value: str) -> str:
    return value if value in _PARSER_NAMES else "unknown"


def _safe_template_code(value: str) -> str:
    if len(value) <= MAX_TEMPLATE_CODE_LENGTH and _SAFE_TEMPLATE_CODE.fullmatch(value):
        return value
    return "auto-v1"


def _safe_terminal_code(value: str | None) -> str | None:
    return value if value in _TERMINAL_CODES else "protocol" if value else None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
