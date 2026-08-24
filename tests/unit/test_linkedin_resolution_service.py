"""F9.1 transient Gmail orchestration tests."""

import pytest

from role_radar.mailbox.contracts import (
    MailboxMessageRef,
    MailboxPreflight,
    ParseResult,
    ReviewProposal,
)
from role_radar.mailbox.linkedin_resolution.contracts import HeadResolutionReport
from role_radar.services.linkedin_resolution_service import LinkedInResolutionMailboxService

RAW_MESSAGE = (
    b"From: alerts@linkedin.com\r\n"
    b"Subject: Job Alert\r\n"
    b"Authentication-Results: mx.google.com; dmarc=pass; header.from=linkedin.com\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
    b"Job Alert https://www.linkedin.com/jobs/1?trk=redacted\r\n"
)


class FakeProvider:
    def __init__(self) -> None:
        self.closed = False

    async def preflight(self) -> MailboxPreflight:
        return MailboxPreflight(53, "RoleRadar", True, "app_password")

    async def get_uidvalidity(self) -> int:
        return 53

    async def list_uids(self, **_kwargs: object) -> tuple[MailboxMessageRef, ...]:
        return (MailboxMessageRef(53, 42, -1),)

    async def fetch(self, _message: MailboxMessageRef) -> bytes:
        return RAW_MESSAGE

    async def close(self) -> None:
        self.closed = True


class FixedParser:
    def parse(self, _profile: str, _message: object) -> ParseResult:
        return ParseResult(
            "linkedin",
            "linkedin-v1",
            (ReviewProposal("link", "email_intake_only", "https://www.linkedin.com/jobs/1"),),
            "recognized",
            None,
        )


class FakeResolver:
    async def resolve(self, proposal: object) -> HeadResolutionReport:
        return HeadResolutionReport("review", 0, 0, None, "internal")


@pytest.mark.asyncio
async def test_service_builds_transient_proposal_and_closes_provider() -> None:
    provider = FakeProvider()
    report = await LinkedInResolutionMailboxService(
        provider,
        FakeResolver(),  # type: ignore[arg-type]
        parser_registry=FixedParser(),  # type: ignore[arg-type]
    ).run()

    assert report.terminal_code == "internal"
    assert provider.closed
    assert "www.linkedin.com/jobs" not in str(report.as_dict())


def test_report_serializer_is_bounded_and_allowlisted() -> None:
    report = HeadResolutionReport("review", 99, 99, None, "secret-url-and-ip")

    output = report.as_dict()

    assert output["request_count"] == 3
    assert output["redirect_count"] == 2
    assert output["terminal_code"] == "internal"
