"""Transcript-only IMAP command and lifecycle tests."""

from __future__ import annotations

import builtins
import imaplib
from typing import Any

import pytest

from role_radar.mailbox.contracts import CredentialMaterial, MailboxDescriptor
from role_radar.mailbox.imap_provider import GmailImapProvider, ImapProviderError


class Transcript:
    def __init__(self) -> None:
        self.commands: list[tuple[str, object]] = []

    def authenticate(self, mechanism: str, callback: object) -> tuple[str, list[bytes]]:
        self.commands.append(("AUTH", mechanism))
        return "OK", []

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
        self.commands.append(("LOGIN", user))
        return "OK", []

    def list(self, *args: str) -> tuple[str, builtins.list[bytes]]:
        self.commands.append(("LIST", args))
        return "OK", [b'(\\HasNoChildren) "/" "RoleRadar"']

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, builtins.list[bytes]]:
        self.commands.append(("SELECT", (mailbox, readonly)))
        return "OK", [b"1"]

    def response(self, code: str) -> tuple[str, builtins.list[bytes]] | None:
        assert code == "UIDVALIDITY"
        return "UIDVALIDITY", [b"9"]

    def uid(self, command: str, *args: str) -> tuple[str, builtins.list[Any]]:
        self.commands.append((command, args))
        if command == "SEARCH":
            return "OK", [b"4 2 3 4"]
        if args[-1] == "(RFC822.SIZE)":
            return "OK", [b"4 (RFC822.SIZE 5)"]
        return "OK", [(b"4 (BODY.PEEK[] {5})", b"hello"), b")"]

    def logout(self) -> tuple[str, builtins.list[bytes]]:
        self.commands.append(("LOGOUT", None))
        return "BYE", []


@pytest.mark.asyncio
async def test_gmail_provider_is_uid_only_readonly_and_peek() -> None:
    transcript = Transcript()
    descriptor = MailboxDescriptor(
        "role-radar",
        "imap",
        "imap.gmail.com",
        993,
        True,
        True,
        "RoleRadar",
        True,
        "xoauth2",
        "u",
        "o",
    )
    provider = GmailImapProvider(
        descriptor,
        CredentialMaterial("u", oauth2_token="oauth"),
        session_factory=lambda _descriptor, _credentials: transcript,
    )
    await provider.preflight()
    refs = await provider.list_uids(uidvalidity=9, after_uid=1, limit=100)
    assert await provider.fetch(refs[0]) == b"hello"
    await provider.close()
    commands = [name for name, _value in transcript.commands]
    assert commands == ["AUTH", "LIST", "SELECT", "SEARCH", "FETCH", "FETCH", "LOGOUT"]
    assert transcript.commands[1] == ("LIST", ('""', "RoleRadar"))
    assert all(name not in commands for name in {"STORE", "MOVE", "COPY", "DELETE", "EXPUNGE"})


class ListProtocolErrorTranscript(Transcript):
    def list(self, *args: str) -> tuple[str, builtins.list[bytes]]:
        del args
        raise imaplib.IMAP4.error("server detail must stay private")


@pytest.mark.asyncio
async def test_gmail_provider_sanitizes_imap_protocol_errors() -> None:
    transcript = ListProtocolErrorTranscript()
    descriptor = MailboxDescriptor(
        "role-radar",
        "imap",
        "imap.gmail.com",
        993,
        True,
        True,
        "RoleRadar",
        True,
        "xoauth2",
        "u",
        "o",
    )
    provider = GmailImapProvider(
        descriptor,
        CredentialMaterial("u", oauth2_token="oauth"),
        session_factory=lambda _descriptor, _credentials: transcript,
    )

    with pytest.raises(ImapProviderError) as error:
        await provider.preflight()

    assert error.value.code == "protocol"
    assert "server detail" not in str(error.value)
