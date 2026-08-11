"""F9.1 attestation and deny-by-default tests."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from role_radar.mailbox.linkedin_resolution.dns import (
    ATTESTATION_SCHEMA,
    AttestedDNSResolver,
    AttestedEgressGuard,
    DNSResolutionError,
    SystemdAttestationStore,
)
from role_radar.mailbox.linkedin_resolution.policy import POLICY_VERSION


class FakeCredentialResolver:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def text(self, _handle: str) -> str:
        return json.dumps(self.payload)


def payload(*, addresses: object = None, expires_at: str | None = None) -> dict[str, object]:
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "policy_version": POLICY_VERSION,
        "expires_at": expires_at
        or (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "hosts": addresses
        or {
            "ar.linkedin.com": ["8.8.8.8"],
            "www.linkedin.com": ["8.8.4.4"],
        },
    }


@pytest.mark.asyncio
async def test_attested_resolver_never_calls_system_dns() -> None:
    store = SystemdAttestationStore(FakeCredentialResolver(payload()))

    assert await AttestedDNSResolver(store).resolve("www.linkedin.com") == ("8.8.4.4",)
    await AttestedEgressGuard(store).assert_ready()
    await AttestedEgressGuard(store).assert_allowed("www.linkedin.com", "8.8.4.4")


def test_attestation_rejects_expired_or_private_values() -> None:
    expired = payload(expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())
    with pytest.raises(DNSResolutionError, match="internal"):
        SystemdAttestationStore(FakeCredentialResolver(expired)).load()

    private = payload(
        addresses={
            "ar.linkedin.com": ["10.0.0.1"],
            "www.linkedin.com": ["8.8.4.4"],
        }
    )
    with pytest.raises(DNSResolutionError, match="internal"):
        SystemdAttestationStore(FakeCredentialResolver(private)).load()


@pytest.mark.asyncio
async def test_attested_egress_rejects_ip_not_in_attestation() -> None:
    store = SystemdAttestationStore(FakeCredentialResolver(payload()))

    with pytest.raises(DNSResolutionError, match="dns_rebinding"):
        await AttestedEgressGuard(store).assert_allowed("www.linkedin.com", "8.8.8.8")
