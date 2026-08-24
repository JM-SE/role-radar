"""Bounded report-only mailbox smoke tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from role_radar.cli.main import _run_mailbox
from role_radar.mailbox.contracts import (
    MailboxErrorCode,
    MailboxMessageRef,
    MailboxPreflight,
    ParseResult,
)
from role_radar.mailbox.imap_provider import ImapProviderError
from role_radar.services.mailbox_smoke_service import MailboxSmokeService

RAW_MESSAGE = (
    b"From: alerts@linkedin.com\r\n"
    b"Subject: Job Alert\r\n"
    b"Authentication-Results: mx.google.com; dmarc=pass; header.from=linkedin.com\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Job Alert https://boards.greenhouse.io/acme/jobs/1\r\n"
)


class FakeProvider:
    def __init__(self, refs: tuple[MailboxMessageRef, ...] = ()) -> None:
        self.refs = refs
        self.calls: list[tuple[str, object]] = []
        self.closed = False

    async def preflight(self) -> MailboxPreflight:
        self.calls.append(("preflight", None))
        return MailboxPreflight(53, "RoleRadar", True, "app_password")

    async def get_uidvalidity(self) -> int:
        return 53

    async def list_uids(self, **kwargs: object) -> tuple[MailboxMessageRef, ...]:
        self.calls.append(("list_uids", kwargs))
        return self.refs

    async def fetch(self, message: MailboxMessageRef) -> bytes:
        self.calls.append(("fetch", message.uid))
        return RAW_MESSAGE

    async def close(self) -> None:
        self.calls.append(("close", None))
        self.closed = True


class FixedParser:
    def parse(self, _profile: str, _message: object) -> ParseResult:
        return ParseResult("linkedin", "linkedin-v1", (), "auto-v1:fixed", None)


@pytest.mark.asyncio
async def test_smoke_selects_one_newest_message_and_does_not_persist() -> None:
    provider = FakeProvider((MailboxMessageRef(53, 42, -1),))
    result = await MailboxSmokeService(
        provider,
        parser_profile="auto",
        parser_registry=FixedParser(),  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 10, tzinfo=UTC),
    ).run()

    assert result.as_dict() == {
        "validated": True,
        "messages_selected": 1,
        "messages_fetched": 1,
        "parser_name": "linkedin",
        "template_code": "auto-v1:fixed",
        "terminal_code": None,
        "output_count": 0,
        "readonly": True,
    }
    assert provider.closed
    assert provider.calls[1][0] == "list_uids"
    assert provider.calls[1][1]["limit"] == 1  # type: ignore[index]
    assert provider.calls[-1] == ("close", None)


@pytest.mark.asyncio
async def test_smoke_empty_lookback_is_success_without_fetch() -> None:
    provider = FakeProvider()
    result = await MailboxSmokeService(provider, parser_profile="auto").run()

    assert result.validated
    assert result.messages_selected == 0
    assert result.messages_fetched == 0
    assert not any(name == "fetch" for name, _value in provider.calls)
    assert provider.closed


@pytest.mark.asyncio
async def test_smoke_sanitizes_parser_failures() -> None:
    provider = FakeProvider((MailboxMessageRef(53, 42, -1),))

    class ExplodingParser:
        def parse(self, _profile: str, _message: object) -> ParseResult:
            raise ValueError("subject body account@example.test https://secret.test")

    result = await MailboxSmokeService(
        provider,
        parser_profile="auto",
        parser_registry=ExplodingParser(),  # type: ignore[arg-type]
    ).run()

    assert result.terminal_code == "malformed"
    assert "account@example.test" not in str(result.as_dict())
    assert "secret.test" not in str(result.as_dict())


@pytest.mark.asyncio
async def test_smoke_preserves_selected_count_when_fetch_fails() -> None:
    class FailingProvider(FakeProvider):
        async def fetch(self, message: MailboxMessageRef) -> bytes:
            self.calls.append(("fetch", message.uid))
            raise ImapProviderError(MailboxErrorCode.MESSAGE_LIMIT.value)

    provider = FailingProvider((MailboxMessageRef(53, 42, -1),))
    result = await MailboxSmokeService(provider, parser_profile="auto").run()

    assert result.as_dict() == {
        "validated": False,
        "messages_selected": 1,
        "messages_fetched": 0,
        "parser_name": "unknown",
        "template_code": "auto-v1",
        "terminal_code": "message_limit",
        "output_count": 0,
        "readonly": True,
    }


def test_smoke_requires_live_ack_before_opening_database() -> None:
    args = type("Args", (), {"mailbox_command": "smoke", "ack_live": False})()
    assert _run_mailbox(None, args) == 4  # type: ignore[arg-type]
