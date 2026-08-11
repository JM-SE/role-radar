"""F9.1 redirect state-machine tests."""

import pytest

from role_radar.mailbox.linkedin_resolution.contracts import (
    AuthenticatedLinkedInProposal,
    HeadResponse,
)
from role_radar.mailbox.linkedin_resolution.resolver import LinkedInHeadResolver

PROPOSAL = AuthenticatedLinkedInProposal(
    "source", "receipt", "proposal", "linkedin", "v1", "recognized", "pass",
    "https://www.linkedin.com/jobs/1?trk=redacted",
)


class FakeDNS:
    async def resolve(self, _host: str) -> tuple[str, ...]:
        return ("8.8.8.8",)


class FakeEgress:
    async def assert_ready(self) -> None:
        return None

    async def assert_allowed(self, _host: str, _address: str) -> None:
        return None


class FakeTransport:
    def __init__(self, responses: tuple[HeadResponse, ...]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, str]] = []

    async def head(self, url: str, *, host: str, address: str, deadline: float) -> HeadResponse:
        self.calls.append((url, host, address))
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_resolver_stops_before_requesting_exact_ats() -> None:
    transport = FakeTransport(
        (HeadResponse(302, "https://boards.greenhouse.io/acme/jobs/eng-1"),)
    )
    report = await LinkedInHeadResolver(transport, FakeDNS(), FakeEgress()).resolve(PROPOSAL)

    assert report.as_dict()["result"] == "intake"
    assert report.request_count == 1
    assert report.redirect_count == 1
    assert report.final_ats is not None
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_resolver_limits_hops_and_no_retries() -> None:
    transport = FakeTransport(
        (
            HeadResponse(302, "/jobs/2"),
            HeadResponse(302, "/jobs/3"),
            HeadResponse(302, "/jobs/4"),
        )
    )
    report = await LinkedInHeadResolver(transport, FakeDNS(), FakeEgress()).resolve(PROPOSAL)

    assert report.terminal_code == "request_limit"
    assert report.request_count == 3
    assert len(transport.calls) == 3


@pytest.mark.asyncio
async def test_resolver_rejects_redirect_to_unknown_host() -> None:
    transport = FakeTransport((HeadResponse(302, "https://evil.example/x"),))
    report = await LinkedInHeadResolver(transport, FakeDNS(), FakeEgress()).resolve(PROPOSAL)

    assert report.terminal_code == "allowlist_rejected"


@pytest.mark.asyncio
async def test_resolver_opens_circuit_on_rate_limit() -> None:
    transport = FakeTransport((HeadResponse(429), HeadResponse(302, "/jobs/2")))
    report = await LinkedInHeadResolver(transport, FakeDNS(), FakeEgress()).resolve(PROPOSAL)

    assert report.terminal_code == "rate_limited"
    assert report.request_count == 1
    assert len(transport.calls) == 1
