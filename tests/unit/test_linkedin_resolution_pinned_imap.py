"""Pinned Gmail IMAP transport tests for F9.1."""

import socket

import pytest

from role_radar.mailbox.imap_provider import ImapProviderError
from role_radar.mailbox.linkedin_resolution.pinned_imap import (
    _connect_pinned_tls,
    pinned_gmail_session_factory,
)


class FakeSocket:
    def __init__(self, peer: str = "8.8.8.8") -> None:
        self.peer = peer
        self.destination: object = None
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def connect(self, destination: object) -> None:
        self.destination = destination

    def getpeername(self) -> tuple[str, int]:
        return self.peer, 993

    def close(self) -> None:
        self.closed = True


class FakeContext:
    def __init__(self) -> None:
        self.server_hostname: str | None = None

    def wrap_socket(self, sock: object, *, server_hostname: str) -> object:
        self.server_hostname = server_hostname
        return sock


def test_pinned_tls_connects_to_numeric_ip_and_preserves_gmail_sni(monkeypatch) -> None:
    sock = FakeSocket()
    context = FakeContext()
    monkeypatch.setattr(socket, "socket", lambda *_args: sock)

    result = _connect_pinned_tls(
        "8.8.8.8",
        "imap.gmail.com",
        993,
        context,  # type: ignore[arg-type]
        2.0,
    )

    assert result is sock
    assert sock.destination == ("8.8.8.8", 993)
    assert context.server_hostname == "imap.gmail.com"


def test_pinned_factory_rejects_missing_or_private_addresses() -> None:
    with pytest.raises(ImapProviderError, match="config"):
        pinned_gmail_session_factory(())
    with pytest.raises(ImapProviderError, match="config"):
        pinned_gmail_session_factory(("127.0.0.1",))
