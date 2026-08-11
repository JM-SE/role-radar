"""Pinned Gmail IMAP session factory for the F9.1 transient gate."""

from __future__ import annotations

import imaplib
import ipaddress
import socket
import ssl
from typing import cast

from role_radar.mailbox.contracts import CredentialMaterial, MailboxDescriptor, MailboxErrorCode
from role_radar.mailbox.imap_provider import ImapProviderError, ImapSession, SessionFactory

GMAIL_IMAP_HOST = "imap.gmail.com"


def pinned_gmail_session_factory(addresses: tuple[str, ...]) -> SessionFactory:
    """Build a factory that connects to one attested IP without DNS."""
    parsed = _public_addresses(addresses)
    address = str(sorted(parsed, key=lambda item: (item.version, int(item)))[0])

    def create(
        descriptor: MailboxDescriptor,
        _credentials: CredentialMaterial,
    ) -> ImapSession:
        if descriptor.host != GMAIL_IMAP_HOST:
            raise ImapProviderError(MailboxErrorCode.CONFIG.value)
        return cast(
            ImapSession,
            _PinnedIMAP4SSL(
                descriptor.host,
                address,
                descriptor.port,
                timeout=15.0,
            ),
        )

    return create


class _PinnedIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, host: str, address: str, port: int, *, timeout: float) -> None:
        self._pinned_address = address
        super().__init__(
            host,
            port,
            ssl_context=ssl.create_default_context(),
            timeout=timeout,
        )

    def _create_socket(self, timeout: float | None) -> ssl.SSLSocket:
        return _connect_pinned_tls(
            self._pinned_address,
            self.host,
            self.port,
            self.ssl_context,
            timeout,
        )


def _connect_pinned_tls(
    address: str,
    server_hostname: str,
    port: int,
    context: ssl.SSLContext,
    timeout: float | None,
) -> ssl.SSLSocket:
    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout)
        destination: tuple[str, int] | tuple[str, int, int, int] = (
            (address, port, 0, 0) if parsed.version == 6 else (address, port)
        )
        raw.connect(destination)
        peer = ipaddress.ip_address(str(raw.getpeername()[0]))
        if peer != parsed:
            raise ImapProviderError(MailboxErrorCode.CONNECTION.value)
        return context.wrap_socket(raw, server_hostname=server_hostname)
    except Exception:
        raw.close()
        raise


def _public_addresses(
    values: tuple[str, ...],
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ImapProviderError(MailboxErrorCode.CONFIG.value) from exc
        if (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
            or (isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None)
        ):
            raise ImapProviderError(MailboxErrorCode.CONFIG.value)
        parsed.append(address)
    if not parsed:
        raise ImapProviderError(MailboxErrorCode.CONFIG.value)
    return tuple(parsed)
