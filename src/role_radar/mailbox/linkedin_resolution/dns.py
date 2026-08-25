"""DNS validation, application pinning, and egress guard seams for F9.1."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from role_radar.acquisition.credentials import CredentialError, CredentialResolver
from role_radar.mailbox.linkedin_resolution.policy import LINKEDIN_HOSTS, POLICY_VERSION

ATTESTATION_SCHEMA = "role-radar-f91-egress-v1"
ATTESTATION_HANDLE = "f91-egress-attestation"
MAILBOX_EGRESS_HOSTS = frozenset({"imap.gmail.com"})
ATTESTED_EGRESS_HOSTS = LINKEDIN_HOSTS | MAILBOX_EGRESS_HOSTS


class DNSResolutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DNSResolver(Protocol):
    async def resolve(self, host: str) -> tuple[str, ...]: ...


class CredentialTextResolver(Protocol):
    def text(self, handle: str) -> str: ...


class EgressGuard(Protocol):
    async def assert_ready(self) -> None: ...

    async def assert_allowed(self, host: str, address: str) -> None: ...


@dataclass(frozen=True, slots=True)
class EgressAttestation:
    expires_at: datetime
    hosts: dict[str, tuple[str, ...]]


class AttestationStore(Protocol):
    def load(self) -> EgressAttestation: ...


class SystemdAttestationStore:
    """Read one immutable root-managed systemd credential per operation."""

    def __init__(
        self,
        resolver: CredentialTextResolver | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._resolver: CredentialTextResolver = resolver or CredentialResolver()
        self._clock = clock or (lambda: datetime.now(UTC))

    def load(self) -> EgressAttestation:
        try:
            raw = self._resolver.text(ATTESTATION_HANDLE)
            payload = json.loads(raw)
        except (CredentialError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DNSResolutionError("internal") from exc
        if not isinstance(payload, dict):
            raise DNSResolutionError("internal")
        if payload.get("schema_version") != ATTESTATION_SCHEMA:
            raise DNSResolutionError("internal")
        if payload.get("policy_version") != POLICY_VERSION:
            raise DNSResolutionError("internal")
        expires_at = _parse_expiry(payload.get("expires_at"))
        if expires_at <= self._clock().astimezone(UTC):
            raise DNSResolutionError("internal")
        raw_hosts = payload.get("hosts")
        if not isinstance(raw_hosts, dict) or set(raw_hosts) != ATTESTED_EGRESS_HOSTS:
            raise DNSResolutionError("internal")
        hosts: dict[str, tuple[str, ...]] = {}
        for host, values in raw_hosts.items():
            if not isinstance(host, str) or host not in ATTESTED_EGRESS_HOSTS:
                raise DNSResolutionError("internal")
            if not isinstance(values, list) or not values:
                raise DNSResolutionError("internal")
            parsed = tuple(dict.fromkeys(str(value) for value in values))
            if any(not _is_valid_attested_ip(value) for value in parsed):
                raise DNSResolutionError("internal")
            hosts[host] = parsed
        return EgressAttestation(expires_at, hosts)


class AttestedDNSResolver:
    def __init__(self, store: AttestationStore) -> None:
        self._store = store

    async def resolve(self, host: str) -> tuple[str, ...]:
        attestation = self._store.load()
        addresses = attestation.hosts.get(host)
        if addresses is None:
            raise DNSResolutionError("allowlist_rejected")
        return addresses


class AttestedEgressGuard:
    def __init__(self, store: AttestationStore) -> None:
        self._store = store

    async def assert_ready(self) -> None:
        self._store.load()

    async def assert_allowed(self, host: str, address: str) -> None:
        attestation = self._store.load()
        if address not in attestation.hosts.get(host, ()):
            raise DNSResolutionError("dns_rebinding")


class SystemDNSResolver:
    async def resolve(self, host: str) -> tuple[str, ...]:
        try:
            rows = await asyncio.to_thread(
                socket.getaddrinfo,
                host,
                443,
                0,
                socket.SOCK_STREAM,
            )
        except (OSError, socket.gaierror) as exc:
            raise DNSResolutionError("dns_failure") from exc
        addresses = tuple(dict.fromkeys(str(row[4][0]) for row in rows))
        if not addresses:
            raise DNSResolutionError("dns_failure")
        return addresses


class FailClosedEgressGuard:
    """Production default until infrastructure attestation is installed."""

    async def assert_ready(self) -> None:
        raise DNSResolutionError("internal")

    async def assert_allowed(self, _host: str, _address: str) -> None:
        raise DNSResolutionError("internal")


async def pin_public_address(
    host: str,
    resolver: DNSResolver,
    egress: EgressGuard,
    *,
    deadline: float,
) -> str:
    remaining = max(0.001, deadline - asyncio.get_running_loop().time())
    try:
        async with asyncio.timeout(remaining):
            await egress.assert_ready()
            addresses = await resolver.resolve(host)
            parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
            for value in addresses:
                try:
                    address = ipaddress.ip_address(value)
                except ValueError as exc:
                    raise DNSResolutionError("dns_failure") from exc
                if not _is_public_address(address):
                    raise DNSResolutionError("dns_private_address")
                parsed.append(address)
            if not parsed:
                raise DNSResolutionError("dns_failure")
            selected = str(sorted(parsed, key=lambda item: (item.version, int(item)))[0])
            await egress.assert_allowed(host, selected)
            return selected
    except TimeoutError as exc:
        raise DNSResolutionError("timeout_operation") from exc


def _is_public_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def _is_valid_attested_ip(value: str) -> bool:
    try:
        return _is_public_address(ipaddress.ip_address(value))
    except ValueError:
        return False


def _parse_expiry(value: object) -> datetime:
    if not isinstance(value, str):
        raise DNSResolutionError("internal")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DNSResolutionError("internal") from exc
    if parsed.tzinfo is None:
        raise DNSResolutionError("internal")
    return parsed.astimezone(UTC)
