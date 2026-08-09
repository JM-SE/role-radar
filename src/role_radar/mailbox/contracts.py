"""Small immutable contracts shared by mailbox adapters and the worker.

The objects in this module deliberately contain no ORM references and no
credential values.  Message bytes are transient and are never part of a
durable contract.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol


class MailboxErrorCode(StrEnum):
    CONFIG = "config"
    CREDENTIALS = "credentials"
    AUTH = "auth"
    CONNECTION = "connection"
    TIMEOUT = "timeout"
    BYE = "bye"
    PROTOCOL = "protocol"
    LABEL_NOT_FOUND = "label_not_found"
    LABEL_NOT_EXACT = "label_not_exact"
    UIDVALIDITY_CHANGED = "uidvalidity_changed"
    MESSAGE_LIMIT = "message_limit"
    MIME_LIMIT = "mime_limit"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    TEMPLATE_DRIFT = "template_drift"
    REVIEW = "review"
    SQL = "sql"


@dataclass(frozen=True, slots=True)
class MailboxDescriptor:
    connection_alias: str
    protocol: str
    host: str
    port: int
    tls: bool
    validate_certificate: bool
    mailbox: str
    readonly: bool
    auth_mode: str
    username_handle: str
    oauth2_handle: str | None = None
    app_password_handle: str | None = None
    message_hmac_handle: str = "mailbox-message-hmac"
    content_hmac_handle: str = "mailbox-content-hmac"


@dataclass(frozen=True, slots=True)
class CredentialMaterial:
    """Worker-only material; never put this object in a plan or log record."""

    username: str
    oauth2_token: str | None = None
    app_password: str | None = None


CredentialResolver = Callable[[MailboxDescriptor], CredentialMaterial]


@dataclass(frozen=True, slots=True)
class MailboxPreflight:
    uidvalidity: int
    mailbox: str
    readonly: bool
    auth_mode: str


@dataclass(frozen=True, slots=True)
class MailboxMessageRef:
    uidvalidity: int
    uid: int
    announced_size: int


@dataclass(frozen=True, slots=True)
class BoundedMailboxMessage:
    """Sanitized MIME output.  No RFC822 bytes or arbitrary headers survive."""

    sender_domain: str | None
    list_id: str | None
    auth_evidence: str
    subject: str
    text: str
    html: str
    urls: tuple[str, ...] = ()
    received_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class LinkLead:
    url: str
    kind: str
    parser_name: str
    parser_version: str


@dataclass(frozen=True, slots=True)
class ReviewProposal:
    kind: str
    reason: str
    url: str | None = None
    parser_name: str = "unknown"
    parser_version: str = "1"


@dataclass(frozen=True, slots=True)
class TerminalRejection:
    code: str
    parser_name: str = "unknown"
    parser_version: str = "1"


ParseOutput = LinkLead | ReviewProposal | TerminalRejection


@dataclass(frozen=True, slots=True)
class ParseResult:
    parser_name: str
    schema_version: str
    outputs: tuple[ParseOutput, ...] = ()
    template_code: str = "unknown"
    terminal_code: str | None = None


@dataclass(frozen=True, slots=True)
class MailboxStateSnapshot:
    source_id: str
    uidvalidity: int | None
    highest_terminal_uid: int
    revision: int


class MailboxProvider(Protocol):
    async def preflight(self) -> MailboxPreflight: ...

    async def get_uidvalidity(self) -> int: ...

    async def list_uids(
        self,
        *,
        uidvalidity: int,
        since: datetime | None = None,
        after_uid: int | None = None,
        limit: int = 100,
    ) -> tuple[MailboxMessageRef, ...]: ...

    async def fetch(self, message: MailboxMessageRef) -> bytes: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class MailboxTask:
    source_id: str
    source_key: str
    connection_alias: str
    parser_profile: str
    operation_id: str
    state: MailboxStateSnapshot
    initial_read: bool
    lookback_started_at: datetime | None
    uid_limit: int


@dataclass(frozen=True, slots=True)
class MailboxPlan:
    run_id: str
    tasks: tuple[MailboxTask, ...]
    scheduled: bool


@dataclass(frozen=True, slots=True)
class MailboxFetchedMessage:
    task: MailboxTask
    message: MailboxMessageRef
    raw: bytes | None = field(default=None, repr=False)
    terminal_code: str | None = None


@dataclass(frozen=True, slots=True)
class MailboxExecution:
    plan: MailboxPlan
    messages: tuple[MailboxFetchedMessage, ...]
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class MailboxFinalization:
    run_id: str
    messages: int
    terminal: int
    proposals: int
    error_code: str | None = None
