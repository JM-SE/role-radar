"""F9.0 report-only service tests."""

from datetime import UTC, datetime

import pytest

from role_radar.mailbox.contracts import MailboxMessageRef, MailboxPreflight, ParseResult
from role_radar.services.linkedin_link_host_audit_service import (
    LinkedInLinkHostAuditService,
)

RAW_MESSAGE = (
    b"From: alerts@linkedin.com\r\n"
    b"Subject: Job Alert\r\n"
    b"Authentication-Results: mx.google.com; dmarc=pass; header.from=linkedin.com\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Job Alert https://linkedin.com/jobs/view/1?trk=secret "
    b"https://boards.greenhouse.io/acme/jobs/eng-1\r\n"
)


class FakeProvider:
    def __init__(self, refs: tuple[MailboxMessageRef, ...] = ()) -> None:
        self.refs = refs
        self.calls: list[str] = []

    async def preflight(self) -> MailboxPreflight:
        self.calls.append("preflight")
        return MailboxPreflight(53, "RoleRadar", True, "app_password")

    async def get_uidvalidity(self) -> int:
        return 53

    async def list_uids(self, **_kwargs: object) -> tuple[MailboxMessageRef, ...]:
        self.calls.append("list_uids")
        return self.refs

    async def fetch(self, _message: MailboxMessageRef) -> bytes:
        self.calls.append("fetch")
        return RAW_MESSAGE

    async def close(self) -> None:
        self.calls.append("close")


class FixedParser:
    def parse(self, _profile: str, _message: object) -> ParseResult:
        return ParseResult("linkedin", "linkedin-v1", (), "recognized", None)


@pytest.mark.asyncio
async def test_service_fetches_one_message_and_never_contacts_link_hosts() -> None:
    provider = FakeProvider((MailboxMessageRef(53, 42, -1),))
    report = await LinkedInLinkHostAuditService(
        provider,
        parser_registry=FixedParser(),  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 10, tzinfo=UTC),
    ).run()

    assert report.validated
    assert report.selected == 1
    assert report.fetched == 1
    assert report.total_url_count == 2
    assert "secret" not in str(report.as_dict())
    assert provider.calls == ["preflight", "list_uids", "fetch", "close"]


@pytest.mark.asyncio
async def test_service_rejects_non_linkedin_parser_and_closes() -> None:
    provider = FakeProvider((MailboxMessageRef(53, 42, -1),))

    class OtherParser:
        def parse(self, _profile: str, _message: object) -> ParseResult:
            return ParseResult("generic", "1", (), "recognized", None)

    report = await LinkedInLinkHostAuditService(
        provider, parser_registry=OtherParser()  # type: ignore[arg-type]
    ).run()

    assert report.terminal_code == "parser_mismatch"
    assert provider.calls[-1] == "close"


@pytest.mark.asyncio
async def test_service_empty_mailbox_is_sanitized() -> None:
    provider = FakeProvider()
    report = await LinkedInLinkHostAuditService(provider).run()

    assert report.as_dict()["terminal_code"] == "empty"
    assert report.as_dict()["host_summaries"] == []
