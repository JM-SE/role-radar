"""Scheduled mailbox ingestion: prepare -> external execute -> finalize."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.db.models import JobSearchRun, Source
from role_radar.discovery.contracts import KnownOfficialCandidate
from role_radar.discovery.url_classifier import classify_url
from role_radar.domain.enums import DiscoveryMode, SourceType
from role_radar.mailbox.configuration import EmailSourceConfigV1
from role_radar.mailbox.contracts import (
    BoundedMailboxMessage,
    MailboxErrorCode,
    MailboxExecution,
    MailboxFetchedMessage,
    MailboxFinalization,
    MailboxPlan,
    MailboxProvider,
    MailboxStateSnapshot,
    MailboxTask,
    ParseResult,
)
from role_radar.mailbox.imap_provider import GmailImapProvider, SessionFactory
from role_radar.mailbox.mime_parser import parse_rfc822
from role_radar.mailbox.parser_registry import MailboxParserRegistry, default_registry
from role_radar.repositories.email_link_proposals import EmailLinkProposalRepository
from role_radar.repositories.email_receipts import EmailReceiptRepository
from role_radar.repositories.mailbox_states import MailboxStateRepository

LOOKBACK_DAYS = 14
INITIAL_LIMIT = 200
POLL_LIMIT = 100


class PipelineMailboxService:
    """The only mailbox component allowed to cross from DTOs into SQL."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        provider_factory: Callable[[MailboxTask], MailboxProvider] | None = None,
        descriptor_resolver: Callable[[str], Any] | None = None,
        credential_resolver: Callable[[Any], Any] | None = None,
        imap_session_factory: SessionFactory | None = None,
        parser_registry: MailboxParserRegistry | None = None,
        url_hmac_key: bytes | None = None,
        content_hmac_key: bytes | None = None,
        mailbox_hmac_keys: Mapping[str, tuple[bytes, bytes]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._provider_factory = provider_factory
        self._descriptor_resolver = descriptor_resolver
        self._credential_resolver = credential_resolver
        self._imap_session_factory = imap_session_factory
        self._registry = parser_registry or default_registry()
        self._url_key = url_hmac_key
        self._content_key = content_hmac_key
        self._mailbox_hmac_keys = dict(mailbox_hmac_keys or {})
        self._clock = clock or (lambda: datetime.now(UTC))

    def prepare(self, run_id: str) -> MailboxPlan:
        now = _utc(self._clock())
        with self._session_factory() as session:
            run = session.get(JobSearchRun, run_id)
            if run is None:
                raise LookupError("run not found")
            scheduled = (
                DiscoveryMode(getattr(run.discovery_mode, "value", run.discovery_mode))
                is DiscoveryMode.SCHEDULED_DUE
            )
            if not scheduled:
                return MailboxPlan(run_id, (), False)
            states = MailboxStateRepository(session)
            tasks: list[MailboxTask] = []
            for source in session.scalars(
                select(Source)
                .where(
                    Source.type == SourceType.EMAIL,
                    Source.enabled.is_(True),
                    Source.archived_at.is_(None),
                )
                .order_by(Source.id)
            ):
                config = EmailSourceConfigV1.model_validate(dict(source.configuration or {}))
                state = states.ensure(source.id, now=now)
                reserved = states.reserve(source.id, run_id=run_id, now=now)
                if reserved is None:
                    continue
                tasks.append(
                    MailboxTask(
                        source.id,
                        source.source_key,
                        config.connection_alias,
                        config.parser_profile,
                        reserved.operation_id or f"mailbox:{run_id}:{source.id}",
                        MailboxStateSnapshot(
                            source.id,
                            state.uidvalidity,
                            state.highest_terminal_uid,
                            reserved.revision,
                        ),
                        state.uidvalidity is None,
                        now - timedelta(days=LOOKBACK_DAYS) if state.uidvalidity is None else None,
                        INITIAL_LIMIT if state.uidvalidity is None else POLL_LIMIT,
                        source.revision,
                        "auto-v1",
                    )
                )
            session.commit()
            return MailboxPlan(run_id, tuple(tasks), True)

    async def execute(self, plan: MailboxPlan) -> MailboxExecution:
        if (
            not plan.scheduled
            or (
                self._provider_factory is None
                and (
                    self._descriptor_resolver is None
                    or self._credential_resolver is None
                )
            )
        ):
            return (
                MailboxExecution(plan, (), "credentials")
                if plan.tasks
                else MailboxExecution(plan, ())
            )
        fetched: list[MailboxFetchedMessage] = []
        first_error: str | None = None
        for task in plan.tasks:
            url_hmac_key, content_hmac_key = self._keys_for(task)
            if url_hmac_key is None or content_hmac_key is None:
                first_error = first_error or MailboxErrorCode.CREDENTIALS.value
                continue
            # The reservation is the durable point of no-repeat.  Commit it
            # before the first await/provider I/O and never retain ORM state.
            with self._session_factory() as session:
                source = session.get(Source, task.source_id)
                started = bool(
                    source is not None
                    and source.revision == task.source_revision
                    and MailboxStateRepository(session).mark_started(
                        task.source_id,
                        operation_id=task.operation_id,
                        now=_utc(self._clock()),
                    )
                )
                session.commit()
            if not started:
                first_error = first_error or "configuration_changed"
                continue
            provider = (
                self._provider_factory(task)
                if self._provider_factory
                else self._default_provider(task)
            )
            try:
                preflight = await provider.preflight()
                if (
                    task.state.uidvalidity is not None
                    and preflight.uidvalidity != task.state.uidvalidity
                ):
                    first_error = first_error or MailboxErrorCode.UIDVALIDITY_CHANGED.value
                    continue
                refs = await provider.list_uids(
                    uidvalidity=preflight.uidvalidity,
                    since=task.lookback_started_at,
                    after_uid=None if task.initial_read else task.state.highest_terminal_uid,
                    limit=task.uid_limit,
                )
                for ref in sorted(refs, key=lambda item: item.uid):
                    try:
                        raw = await provider.fetch(ref)
                        fetched.append(MailboxFetchedMessage(task, ref, raw))
                    except Exception as exc:
                        code = getattr(exc, "code", MailboxErrorCode.CONNECTION.value)
                        fetched.append(MailboxFetchedMessage(task, ref, None, str(code)))
            except Exception as exc:
                first_error = first_error or str(
                    getattr(exc, "code", MailboxErrorCode.CONNECTION.value)
                )
            finally:
                await provider.close()
        return MailboxExecution(plan, tuple(fetched), first_error)

    def _default_provider(self, task: MailboxTask) -> MailboxProvider:
        if self._descriptor_resolver is None or self._credential_resolver is None:
            raise ValueError("mailbox worker resolver unavailable")
        descriptor = self._descriptor_resolver(task.connection_alias)
        credentials = self._credential_resolver(descriptor)
        return GmailImapProvider(
            descriptor,
            credentials,
            session_factory=self._imap_session_factory,
        )

    def finalize(self, execution: MailboxExecution) -> MailboxFinalization:
        terminal = proposals = 0
        processed_sources = {item.task.source_id for item in execution.messages}
        for item in execution.messages:
            url_hmac_key, content_hmac_key = self._keys_for(item.task)
            if url_hmac_key is None or content_hmac_key is None:
                raise ValueError("mailbox HMAC keys unavailable")
            with self._session_factory() as session:
                state = MailboxStateRepository(session).get(item.task.source_id)
                if state is None:
                    raise LookupError("mailbox state not found")
                if state.uidvalidity is not None and state.uidvalidity != item.message.uidvalidity:
                    state.last_error_code = MailboxErrorCode.UIDVALIDITY_CHANGED.value
                    session.commit()
                    continue
                if state.uidvalidity is None:
                    state.uidvalidity = item.message.uidvalidity
                receipts = EmailReceiptRepository(session)
                existing = receipts.get(
                    item.task.source_id, item.message.uidvalidity, item.message.uid
                )
                if existing is not None:
                    state.highest_terminal_uid = max(state.highest_terminal_uid, item.message.uid)
                    state.revision += 1
                    session.commit()
                    continue
                parsed: ParseResult
                message: BoundedMailboxMessage | None = None
                error_code = item.terminal_code
                content_hmac = (
                    _digest(content_hmac_key, item.raw) if item.raw is not None else None
                )
                if error_code is None and item.raw is not None:
                    try:
                        message = parse_rfc822(item.raw)
                        parsed = self._registry.parse(item.task.parser_profile, message)
                    except Exception as exc:
                        code = getattr(exc, "code", MailboxErrorCode.MALFORMED.value)
                        error_code = str(code)
                        parsed = ParseResult("unknown", "1", terminal_code=error_code)
                else:
                    parsed = ParseResult("unknown", "1", terminal_code=error_code or "failed")
                error_code = error_code or parsed.terminal_code
                status = "succeeded" if error_code is None else _receipt_status(error_code)
                created = receipts.create_terminal(
                    id=str(uuid4()),
                    source_id=item.task.source_id,
                    uidvalidity=item.message.uidvalidity,
                    uid=item.message.uid,
                    content_hmac=content_hmac,
                    parser_name=parsed.parser_name,
                    parser_version=parsed.schema_version,
                    status=status,
                    error_code=error_code or parsed.terminal_code,
                    sender_domain=None,
                    list_id=None,
                    auth_evidence=message.auth_evidence if message else "missing",
                    template_code=parsed.template_code,
                    proposal_count=0,
                )
                message_proposals = 0
                for output in parsed.outputs:
                    url = getattr(output, "url", None)
                    safe_url = (
                        _safe_ats_url(url)
                        if output.__class__.__name__ == "LinkLead"
                        else None
                    )
                    reason = getattr(output, "reason", "lead")
                    proposal_status = "intake" if safe_url else "review"
                    kind = "ats_direct" if safe_url else getattr(output, "kind", "message")
                    if kind not in {"ats_direct", "link", "message"}:
                        kind = "message"
                    EmailLinkProposalRepository(session).add(
                        id=str(uuid4()),
                        receipt_id=created.id,
                        url_hmac=_digest(url_hmac_key, url or reason) or "hmac-unavailable",
                        normalized_url=safe_url,
                        parser_name=parsed.parser_name,
                        parser_version=parsed.schema_version,
                        kind=kind,
                        status=proposal_status,
                        reason=reason,
                    )
                    proposals += 1
                    message_proposals += 1
                created.proposal_count = message_proposals
                state.highest_terminal_uid = max(state.highest_terminal_uid, item.message.uid)
                state.last_success_at = _utc(self._clock())
                state.last_error_code = error_code
                state.revision += 1
                terminal += 1
                session.commit()
        for task in execution.plan.tasks:
            if task.source_id in processed_sources:
                continue
            with self._session_factory() as session:
                state = MailboxStateRepository(session).get(task.source_id)
                if state is None:
                    continue
                state.last_error_code = execution.error_code
                if execution.error_code is None:
                    state.last_success_at = _utc(self._clock())
                state.revision += 1
                session.commit()
        for task in execution.plan.tasks:
            with self._session_factory() as session:
                state = MailboxStateRepository(session).get(task.source_id)
                if state is not None and state.operation_id == task.operation_id:
                    seen = [
                        item.message.uid
                        for item in execution.messages
                        if item.task.operation_id == task.operation_id
                    ]
                    task_messages = [
                        item
                        for item in execution.messages
                        if item.task.operation_id == task.operation_id
                    ]
                    MailboxStateRepository(session).finalize(
                        task.source_id,
                        operation_id=task.operation_id,
                        uidvalidity=(
                            task_messages[0].message.uidvalidity
                            if task_messages
                            else state.uidvalidity or 0
                        ),
                        highest_terminal_uid=max(seen, default=state.highest_terminal_uid),
                        now=_utc(self._clock()),
                        error_code=execution.error_code if not seen else None,
                    )
                session.commit()
        return MailboxFinalization(
            execution.plan.run_id,
            len(execution.messages),
            terminal,
            proposals,
            execution.error_code,
        )

    def _keys_for(self, task: MailboxTask) -> tuple[bytes | None, bytes | None]:
        if self._mailbox_hmac_keys:
            return self._mailbox_hmac_keys.get(task.connection_alias, (None, None))
        return self._url_key, self._content_key


def _safe_ats_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.fragment or parsed.query:
        return None
    host = (parsed.hostname or "").lower()
    if host not in {"boards.greenhouse.io", "jobs.lever.co", "jobs.eu.lever.co"}:
        return None
    if not isinstance(classify_url(value), KnownOfficialCandidate):
        return None
    return value[:2048]


def _digest(key: bytes | None, value: bytes | str | None) -> str | None:
    if value is None:
        return None
    material = key or b"worker-hmac-unavailable"
    raw = value if isinstance(value, bytes) else value.encode()
    return hmac.new(material, raw, hashlib.sha256).hexdigest()


def _receipt_status(code: str) -> str:
    if code in {"message_limit", "mime_limit"}:
        return "limit"
    if code in {"unsupported"}:
        return "unsupported"
    if code in {"review", "template_drift"}:
        return "review"
    if code in {"malformed"}:
        return "malformed"
    return "failed"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
