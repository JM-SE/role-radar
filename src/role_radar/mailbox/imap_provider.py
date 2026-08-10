"""Gmail IMAP read-only adapter.

Only this module knows about IMAP commands.  It exposes no ORM and keeps the
credential material in the worker process.  Tests inject a transcript session;
the default seam is the standard-library ``imaplib.IMAP4_SSL`` client.
"""

from __future__ import annotations

import asyncio
import builtins
import imaplib
import re
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from role_radar.mailbox.contracts import (
    CredentialMaterial,
    MailboxDescriptor,
    MailboxErrorCode,
    MailboxMessageRef,
    MailboxPreflight,
    MailboxProvider,
)
from role_radar.mailbox.mime_parser import MAX_RFC822_BYTES

CONNECT_TIMEOUT_SECONDS = 15.0
OPERATION_TIMEOUT_SECONDS = 30.0


class ImapSession(Protocol):
    def authenticate(
        self, mechanism: str, callback: Callable[[bytes], bytes]
    ) -> tuple[str, builtins.list[bytes]]: ...

    def login(self, user: str, password: str) -> tuple[str, builtins.list[bytes]]: ...

    def list(self, *args: str) -> tuple[str, builtins.list[bytes]]: ...

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, builtins.list[bytes]]: ...

    def response(self, code: str) -> tuple[str, builtins.list[bytes]] | None: ...

    def uid(self, command: str, *args: str) -> tuple[str, builtins.list[Any]]: ...

    def logout(self) -> tuple[str, builtins.list[bytes]]: ...


SessionFactory = Callable[[MailboxDescriptor, CredentialMaterial], ImapSession]


class ImapProviderError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GmailImapProvider(MailboxProvider):
    def __init__(
        self,
        descriptor: MailboxDescriptor,
        credentials: CredentialMaterial,
        *,
        session_factory: SessionFactory | None = None,
        operation_timeout: float = OPERATION_TIMEOUT_SECONDS,
    ) -> None:
        _validate_descriptor(descriptor)
        self._descriptor = descriptor
        self._credentials = credentials
        self._session_factory = session_factory or _default_session
        self._operation_timeout = operation_timeout
        self._session: ImapSession | None = None
        self._uidvalidity: int | None = None
        self._closed = False

    async def __aenter__(self) -> GmailImapProvider:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.close()

    async def preflight(self) -> MailboxPreflight:
        session = await self._call(self._open)
        status, rows = await self._call(session.list, '""', self._descriptor.mailbox)
        if status != "OK":
            await self.close()
            raise ImapProviderError(MailboxErrorCode.LABEL_NOT_FOUND.value)
        names = [item.decode("utf-8", "strict") for item in rows if isinstance(item, bytes)]
        if sum(_listed_name(item) == self._descriptor.mailbox for item in names) != 1:
            await self.close()
            raise ImapProviderError(MailboxErrorCode.LABEL_NOT_EXACT.value)
        status, data = await self._call(session.select, self._descriptor.mailbox, True)
        if status != "OK":
            await self.close()
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value)
        response = await self._call(session.response, "UIDVALIDITY")
        response_data = response[1] if response is not None else []
        uidvalidity = _uidvalidity(response_data) or _uidvalidity(data)
        if uidvalidity is None:
            await self.close()
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value)
        self._uidvalidity = uidvalidity
        return MailboxPreflight(
            uidvalidity, self._descriptor.mailbox, True, self._descriptor.auth_mode
        )

    async def get_uidvalidity(self) -> int:
        if self._uidvalidity is None:
            return (await self.preflight()).uidvalidity
        return self._uidvalidity

    async def list_uids(
        self,
        *,
        uidvalidity: int,
        since: datetime | None = None,
        after_uid: int | None = None,
        limit: int = 100,
    ) -> tuple[MailboxMessageRef, ...]:
        del uidvalidity
        if limit <= 0 or limit > 100:
            raise ValueError("UID poll limit must be between 1 and 100")
        session = self._require_session()
        if since is not None and after_uid is not None:
            raise ValueError("initial and subsequent cursor modes are exclusive")
        if since is not None:
            query = "SINCE " + since.strftime("%d-%b-%Y")
        elif after_uid is not None:
            if after_uid < 0:
                raise ValueError("UID must not be negative")
            query = f"UID {after_uid + 1}:*"
        else:
            query = "ALL"
        status, data = await self._call(session.uid, "SEARCH", None, query)
        if status != "OK" or not data:
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value)
        raw_uids = data[0].split() if isinstance(data[0], bytes) else []
        uids = sorted({int(item) for item in raw_uids if item.isdigit()})
        selected = uids[-limit:] if since is not None else uids[:limit]
        current_uidvalidity = self._uidvalidity
        if current_uidvalidity is None:
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value)
        return tuple(MailboxMessageRef(current_uidvalidity, uid, -1) for uid in selected)

    async def fetch(self, message: MailboxMessageRef) -> bytes:
        if message.uid <= 0:
            raise ValueError("UID must be positive")
        session = self._require_session()
        announced = await self.fetch_size(message)
        if announced > MAX_RFC822_BYTES:
            raise ImapProviderError(MailboxErrorCode.MESSAGE_LIMIT.value)
        status, body_data = await self._call(
            session.uid, "FETCH", str(message.uid), "(BODY.PEEK[])"
        )
        body = _fetch_body(body_data)
        if status != "OK" or body is None:
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value)
        if len(body) > MAX_RFC822_BYTES or len(body) != announced:
            raise ImapProviderError(MailboxErrorCode.MESSAGE_LIMIT.value)
        return body

    async def fetch_size(self, message: MailboxMessageRef) -> int:
        if message.uid <= 0:
            raise ValueError("UID must be positive")
        session = self._require_session()
        status, size_data = await self._call(
            session.uid, "FETCH", str(message.uid), "(RFC822.SIZE)"
        )
        announced = _fetch_size(size_data)
        if status != "OK" or announced is None:
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value)
        return announced

    async def close(self) -> None:
        session, self._session = self._session, None
        self._closed = True
        if session is not None:
            with suppress(Exception):
                await self._call(session.logout)

    def _open(self) -> ImapSession:
        if self._session is None:
            self._session = self._session_factory(self._descriptor, self._credentials)
            if self._descriptor.auth_mode == "xoauth2":
                if not self._credentials.oauth2_token:
                    raise ImapProviderError(MailboxErrorCode.CREDENTIALS.value)
                if self._descriptor.oauth2_expiry_handle is not None and (
                    self._credentials.oauth2_expires_at is None
                    or self._credentials.oauth2_expires_at.astimezone(UTC) - datetime.now(UTC)
                    < timedelta(minutes=5)
                ):
                    raise ImapProviderError(MailboxErrorCode.CREDENTIALS.value)
                status, _ = self._session.authenticate(
                    "XOAUTH2",
                    lambda _: (
                        f"user={self._credentials.username}\1"
                        f"auth=Bearer {self._credentials.oauth2_token}\1\1"
                    ).encode(),
                )
            else:
                if not self._credentials.app_password:
                    raise ImapProviderError(MailboxErrorCode.CREDENTIALS.value)
                status, _ = self._session.login(
                    self._credentials.username, self._credentials.app_password
                )
            if status != "OK":
                raise ImapProviderError(MailboxErrorCode.AUTH.value)
        return self._session

    def _require_session(self) -> ImapSession:
        if self._session is None or self._closed:
            raise ImapProviderError(MailboxErrorCode.CONNECTION.value)
        return self._session

    async def _call(self, function: Callable[..., Any], *args: Any) -> Any:
        try:
            async with asyncio.timeout(self._operation_timeout):
                return await asyncio.to_thread(function, *args)
        except asyncio.CancelledError:
            await self.close()
            raise
        except TimeoutError as exc:
            await self.close()
            raise ImapProviderError(MailboxErrorCode.TIMEOUT.value) from exc
        except imaplib.IMAP4.abort as exc:
            await self.close()
            raise ImapProviderError(MailboxErrorCode.CONNECTION.value) from exc
        except imaplib.IMAP4.error as exc:
            await self.close()
            raise ImapProviderError(MailboxErrorCode.PROTOCOL.value) from exc
        except (ConnectionError, OSError) as exc:
            await self.close()
            raise ImapProviderError(MailboxErrorCode.CONNECTION.value) from exc


ImapMailboxProvider = GmailImapProvider


def _default_session(
    descriptor: MailboxDescriptor, _credentials: CredentialMaterial
) -> ImapSession:
    return cast(ImapSession, imaplib.IMAP4_SSL(
        descriptor.host,
        descriptor.port,
        ssl_context=None,
        timeout=CONNECT_TIMEOUT_SECONDS,
    ))


def _validate_descriptor(descriptor: MailboxDescriptor) -> None:
    if (
        descriptor.protocol != "imap"
        or descriptor.host != "imap.gmail.com"
        or descriptor.port != 993
        or not descriptor.tls
        or not descriptor.validate_certificate
        or descriptor.mailbox != "RoleRadar"
        or not descriptor.readonly
    ):
        raise ImapProviderError(MailboxErrorCode.CONFIG.value)


def _listed_name(value: str) -> str | None:
    # ``LIST`` responses are treated as untrusted text; only the quoted final
    # name is compared, never used as a command or fallback mailbox.
    match = re.search(r'"([^"]+)"\s*$', value)
    return match.group(1) if match else None


def _uidvalidity(data: list[bytes]) -> int | None:
    for item in data:
        if item.isdigit():
            return int(item)
        match = re.search(rb"UIDVALIDITY\s+(\d+)", item, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _fetch_size(data: list[bytes]) -> int | None:
    for item in data:
        match = re.search(rb"RFC822\.SIZE\s+(\d+)", item, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _fetch_body(data: list[Any]) -> bytes | None:
    """Extract the RFC822 literal from imaplib's FETCH response.

    ``imaplib`` represents a literal response as ``(metadata, payload)`` and
    appends a separate closing response such as ``b")"``.  Do not treat those
    protocol fragments as a message body: doing so can make the body length
    disagree with RFC822.SIZE and incorrectly produce ``message_limit``.
    """
    for item in data:
        if (
            isinstance(item, tuple)
            and len(item) == 2
            and isinstance(item[0], bytes)
            and isinstance(item[1], bytes)
            and (b"BODY[" in item[0].upper() or b"BODY.PEEK" in item[0].upper())
            and b"}" in item[0]
        ):
            return item[1]
        if (
            isinstance(item, bytes)
            and (b"BODY[" in item.upper() or b"BODY.PEEK" in item.upper())
            and b"}" in item
        ):
            body = item.split(b"}", 1)[1].lstrip(b"\r\n")
            if body.strip(b")\r\n "):
                return body
    return None
