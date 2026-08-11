"""F9.1 DNS/IP pinning and egress tests."""

import asyncio

import pytest

from role_radar.mailbox.linkedin_resolution.dns import (
    DNSResolutionError,
    FailClosedEgressGuard,
    pin_public_address,
)


class FakeDNS:
    def __init__(self, addresses: tuple[str, ...]) -> None:
        self.addresses = addresses
        self.calls = 0

    async def resolve(self, _host: str) -> tuple[str, ...]:
        self.calls += 1
        return self.addresses


class HangingDNS(FakeDNS):
    async def resolve(self, _host: str) -> tuple[str, ...]:
        await asyncio.sleep(10)
        return self.addresses


class FakeEgress:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def assert_ready(self) -> None:
        return None

    async def assert_allowed(self, host: str, address: str) -> None:
        self.calls.append((host, address))


@pytest.mark.asyncio
async def test_pin_validates_once_and_passes_selected_ip_to_egress() -> None:
    dns = FakeDNS(("8.8.8.8",))
    egress = FakeEgress()

    address = await pin_public_address(
        "www.linkedin.com",
        dns,
        egress,
        deadline=asyncio.get_running_loop().time() + 1,
    )

    assert address == "8.8.8.8"
    assert dns.calls == 1
    assert egress.calls == [("www.linkedin.com", "8.8.8.8")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.1.1", "100.64.0.1", "::ffff:8.8.8.8"],
)
async def test_private_reserved_and_mapped_addresses_fail_closed(address: str) -> None:
    with pytest.raises(DNSResolutionError, match="dns_private_address"):
        await pin_public_address(
            "www.linkedin.com",
            FakeDNS((address,)),
            FakeEgress(),
            deadline=asyncio.get_running_loop().time() + 1,
        )


@pytest.mark.asyncio
async def test_unattested_runtime_egress_fails_closed() -> None:
    dns = FakeDNS(("8.8.8.8",))
    with pytest.raises(DNSResolutionError, match="internal"):
        await pin_public_address(
            "www.linkedin.com",
            dns,
            FailClosedEgressGuard(),
            deadline=asyncio.get_running_loop().time() + 1,
        )
    assert dns.calls == 0


@pytest.mark.asyncio
async def test_dns_resolution_is_bounded_by_operation_deadline() -> None:
    with pytest.raises(DNSResolutionError, match="timeout_operation"):
        await pin_public_address(
            "www.linkedin.com",
            HangingDNS(("8.8.8.8",)),
            FakeEgress(),
            deadline=asyncio.get_running_loop().time() + 0.001,
        )
