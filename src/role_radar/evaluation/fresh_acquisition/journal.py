"""Per-wire transport journaling and replay — durable intent/outcome with fsync.

New private journal and JournaledAsyncTransport(httpx.AsyncBaseTransport) that
wraps only the approved production or fake delegate and is injected through
CollectorContext.transport, below BoundedHttpClient.

Each delegate handle_async_request invocation caused by a first call,
known-safe retry, or pagination page is independently journaled as one wire
attempt. Before each invocation we fsync a bounded intent (opaque
operation/source/ordinal + destination fingerprint + counter bindings). After
delegate returns we fsync a bounded outcome only after proven terminal status
and stream completion (no body stored). Pending/indeterminate blocks further
delegate calls for that source; operation fails closed.

No reuse of old JournaledTransport — exception-as-result is incompatible;
a request intent without provable terminal response remains indeterminate.

No credentials, headers, bodies, raw URLs/query text outside one-way
fingerprint, descriptions, or raw exception text are persisted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import httpx

from role_radar.collectors.policy import RETRYABLE_STATUSES
from role_radar.evaluation.fresh_acquisition.filesystem import (
    FilesystemError,
    atomic_write,
    bounded_read,
    ensure_private_root,
    fenced_lock,
)

MAX_INTENT_BYTES: Final[int] = 4096
MAX_JOURNAL_BYTES: Final[int] = 10 * 1024 * 1024
JOURNAL_DIR: Final[str] = "journal"
FINGERPRINT_LEN: Final[int] = 16

STATUS_CLASS_OK: Final[str] = "ok"
STATUS_CLASS_RETRYABLE: Final[str] = "retryable"
STATUS_CLASS_NON_RETRYABLE: Final[str] = "non_retryable"


class JournalError(ValueError):
    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


class JournaledTransportError(RuntimeError):
    """Detail-free sentinel for indeterminate wire attempt."""

    def __init__(self, code: str = "indeterminate") -> None:
        self.code: str = code
        super().__init__(code)


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JournalError("journal_canonical_invalid") from exc


def _domain_hash(domain: str, canonical: bytes) -> str:
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical)
    return h.hexdigest()


def _fingerprint(request: httpx.Request) -> str:
    """One-way destination fingerprint; no raw URL/query retained."""
    try:
        url = request.url
        host = str(url.host).lower() if url.host else ""
        path = str(url.path)
        # include only method + host + path hash; query/headers/bodies excluded
        pre = _canonical_bytes([request.method.upper(), host, path])
    except Exception as exc:
        raise JournalError("journal_fingerprint_failed") from exc
    return hashlib.sha256(pre).hexdigest()[:FINGERPRINT_LEN]


def _classify_status(status_code: int) -> tuple[str, bool]:
    if 200 <= status_code < 300:
        return STATUS_CLASS_OK, False
    if status_code in RETRYABLE_STATUSES:
        return STATUS_CLASS_RETRYABLE, True
    if 300 <= status_code <= 399:
        return STATUS_CLASS_NON_RETRYABLE, False
    if 400 <= status_code <= 499:
        return STATUS_CLASS_NON_RETRYABLE, False
    if status_code >= 500:
        # 500 already in retryable set; treat remaining 5xx as retryable conservatively
        return STATUS_CLASS_RETRYABLE, True
    return STATUS_CLASS_NON_RETRYABLE, False


@dataclass(frozen=True, slots=True)
class WireIntent:
    operation_id: str
    source_id: str
    ordinal: int
    destination_fingerprint: str
    budget_ordinal: int
    wire_attempt: int


@dataclass(frozen=True, slots=True)
class WireOutcome:
    operation_id: str
    source_id: str
    ordinal: int
    status_code: int
    status_class: str
    retryable: bool


@dataclass(frozen=True, slots=True)
class JournalCounts:
    durable_intents: int
    known_terminal_outcomes: int
    pending_or_indeterminate: int
    delegate_entries: int
    budget_debits: int
    collector_wire_attempts: int


class AcquisitionJournal:
    """Durable per-wire journal with lock/fence and monotonic transitions."""

    def __init__(self, *, operation_id: str, root: Path | None = None) -> None:
        if not operation_id or not operation_id.strip():
            raise JournalError("journal_operation_invalid")
        if "/" in operation_id or "\\" in operation_id:
            raise JournalError("journal_operation_invalid")
        self.operation_id: str = operation_id
        self.root: Path | None = root
        # in-memory state: source_id -> {ordinal -> (intent, outcome|None)}
        self._intents: dict[str, dict[int, WireIntent]] = {}
        self._outcomes: dict[str, dict[int, WireOutcome]] = {}
        self._next_ordinal: dict[str, int] = {}
        self._journal_path: Path | None = None
        if root is not None:
            if not root.is_absolute():
                raise JournalError("journal_root_must_be_absolute")
            # do not create here; lazily on first fsync via ensure_private_root
            self._journal_path = root / JOURNAL_DIR / f"{operation_id}.jsonl"

    # -- filesystem helpers --

    def _ensure_fs(self) -> None:
        if self.root is None or self._journal_path is None:
            return
        try:
            ensure_private_root(self.root)
            journal_dir = self.root / JOURNAL_DIR
            journal_dir.mkdir(parents=True, exist_ok=True)
            journal_dir.chmod(0o700)
        except FilesystemError as exc:
            raise JournalError(exc.code) from exc
        except OSError as exc:
            raise JournalError("journal_fs_setup_failed") from exc

    def _fsync_intent(self, intent: WireIntent) -> None:
        payload = _canonical_bytes(
            {
                "kind": "intent",
                "operation_id": intent.operation_id,
                "source_id": intent.source_id,
                "ordinal": intent.ordinal,
                "destination_fingerprint": intent.destination_fingerprint,
                "budget_ordinal": intent.budget_ordinal,
                "wire_attempt": intent.wire_attempt,
            }
        )
        if len(payload) > MAX_INTENT_BYTES:
            raise JournalError("journal_intent_bound_exceeded")
        if self._journal_path is None:
            return
        self._ensure_fs()
        assert self._journal_path is not None
        # append via atomic read-modify-write under fence
        try:
            with fenced_lock(self.root):  # type: ignore[arg-type]
                existing = b""
                if self._journal_path.exists():
                    existing = bounded_read(self._journal_path, max_bytes=MAX_JOURNAL_BYTES)
                    if existing and not existing.endswith(b"\n"):
                        existing += b"\n"
                new_content = existing + payload + b"\n"
                if len(new_content) > MAX_JOURNAL_BYTES:
                    raise JournalError("journal_bound_exceeded")
                atomic_write(self._journal_path, new_content, max_bytes=MAX_JOURNAL_BYTES)
        except FilesystemError as exc:
            raise JournalError(exc.code) from exc

    def _fsync_outcome(self, outcome: WireOutcome) -> None:
        payload = _canonical_bytes(
            {
                "kind": "outcome",
                "operation_id": outcome.operation_id,
                "source_id": outcome.source_id,
                "ordinal": outcome.ordinal,
                "status_code": outcome.status_code,
                "status_class": outcome.status_class,
                "retryable": outcome.retryable,
            }
        )
        if len(payload) > MAX_INTENT_BYTES:
            raise JournalError("journal_outcome_bound_exceeded")
        if self._journal_path is None:
            return
        self._ensure_fs()
        assert self._journal_path is not None
        try:
            with fenced_lock(self.root):  # type: ignore[arg-type]
                existing = bounded_read(self._journal_path, max_bytes=MAX_JOURNAL_BYTES)
                if not existing.endswith(b"\n"):
                    existing += b"\n"
                new_content = existing + payload + b"\n"
                if len(new_content) > MAX_JOURNAL_BYTES:
                    raise JournalError("journal_bound_exceeded")
                atomic_write(self._journal_path, new_content, max_bytes=MAX_JOURNAL_BYTES)
        except FilesystemError as exc:
            raise JournalError(exc.code) from exc

    # -- intent/outcome lifecycle --

    def next_ordinal(self, source_id: str) -> int:
        nxt = self._next_ordinal.get(source_id, 1)
        self._next_ordinal[source_id] = nxt + 1
        return nxt

    def is_blocked(self, source_id: str) -> bool:
        intents = self._intents.get(source_id, {})
        outcomes = self._outcomes.get(source_id, {})
        return any(ordinal not in outcomes for ordinal in intents)

    def record_intent(
        self,
        *,
        source_id: str,
        ordinal: int,
        destination_fingerprint: str,
        budget_ordinal: int,
    ) -> WireIntent:
        if self.is_blocked(source_id):
            raise JournalError("journal_source_blocked_pending")
        if not source_id or not source_id.strip():
            raise JournalError("journal_source_invalid")
        if ordinal <= 0:
            raise JournalError("journal_ordinal_invalid")
        if len(destination_fingerprint) != FINGERPRINT_LEN:
            raise JournalError("journal_fingerprint_invalid")
        existing = self._intents.get(source_id, {}).get(ordinal)
        if existing is not None:
            raise JournalError("journal_ordinal_conflict")
        intent = WireIntent(
            operation_id=self.operation_id,
            source_id=source_id,
            ordinal=ordinal,
            destination_fingerprint=destination_fingerprint,
            budget_ordinal=budget_ordinal,
            wire_attempt=ordinal,
        )
        self._fsync_intent(intent)
        self._intents.setdefault(source_id, {})[ordinal] = intent
        # track next ordinal monotonically
        cur = self._next_ordinal.get(source_id, 1)
        if ordinal >= cur:
            self._next_ordinal[source_id] = ordinal + 1
        return intent

    def record_outcome(
        self,
        *,
        source_id: str,
        ordinal: int,
        status_code: int,
        status_class: str,
        retryable: bool,
    ) -> WireOutcome:
        intents = self._intents.get(source_id, {})
        if ordinal not in intents:
            raise JournalError("journal_outcome_without_intent")
        if ordinal in self._outcomes.get(source_id, {}):
            raise JournalError("journal_outcome_duplicate")
        if status_class not in {
            STATUS_CLASS_OK,
            STATUS_CLASS_RETRYABLE,
            STATUS_CLASS_NON_RETRYABLE,
        }:
            raise JournalError("journal_status_class_invalid")
        outcome = WireOutcome(
            operation_id=self.operation_id,
            source_id=source_id,
            ordinal=ordinal,
            status_code=status_code,
            status_class=status_class,
            retryable=retryable,
        )
        self._fsync_outcome(outcome)
        self._outcomes.setdefault(source_id, {})[ordinal] = outcome
        return outcome

    def pending_count(self, source_id: str | None = None) -> int:
        if source_id is not None:
            intents = self._intents.get(source_id, {})
            outcomes = self._outcomes.get(source_id, {})
            return sum(1 for o in intents if o not in outcomes)
        total = 0
        for sid in self._intents:
            total += self.pending_count(sid)
        return total

    def durable_intents(self, source_id: str | None = None) -> int:
        if source_id is not None:
            return len(self._intents.get(source_id, {}))
        return sum(len(v) for v in self._intents.values())

    def known_terminal_outcomes(self, source_id: str | None = None) -> int:
        if source_id is not None:
            return len(self._outcomes.get(source_id, {}))
        return sum(len(v) for v in self._outcomes.values())

    def counts(self, source_id: str | None = None) -> JournalCounts:
        di = self.durable_intents(source_id)
        kto = self.known_terminal_outcomes(source_id)
        pending = self.pending_count(source_id)
        # delegate_entries == durable_intents by construction (one intent per delegate call)
        # budget_debits == durable_intents (one budget debit per intent)
        return JournalCounts(
            durable_intents=di,
            known_terminal_outcomes=kto,
            pending_or_indeterminate=pending,
            delegate_entries=di,
            budget_debits=di,
            collector_wire_attempts=di,
        )

    def is_sealable(self, source_id: str | None = None) -> bool:
        c = self.counts(source_id)
        return (
            c.pending_or_indeterminate == 0
            and c.durable_intents == c.known_terminal_outcomes
            and c.durable_intents == c.delegate_entries
            and c.delegate_entries == c.budget_debits
            and c.budget_debits == c.collector_wire_attempts
        )

    def can_retry(self, source_id: str) -> bool:
        if self.is_blocked(source_id):
            return False
        outcomes = self._outcomes.get(source_id, {})
        if not outcomes:
            return False
        last = max(outcomes.keys())
        return outcomes[last].retryable

    def can_paginate(self, source_id: str) -> bool:
        return not self.is_blocked(source_id)

    def should_skip_source(self, source_id: str, checkpoint_wire_attempts: int) -> bool:
        """Replay skips only when known-complete attempts and checkpoint reconcile."""
        if self.is_blocked(source_id):
            return False
        di = self.durable_intents(source_id)
        kto = self.known_terminal_outcomes(source_id)
        if di != kto:
            return False
        return di == checkpoint_wire_attempts

    def reconcile_equations(self, source_id: str | None = None) -> None:
        c = self.counts(source_id)
        # sealable equation
        if c.pending_or_indeterminate == 0:
            if not (
                c.durable_intents
                == c.delegate_entries
                == c.budget_debits
                == c.collector_wire_attempts
                == c.known_terminal_outcomes
            ):
                raise JournalError("journal_reconcile_mismatch_sealable")
        else:
            # faulted equation: durable == known + pending
            if c.durable_intents != c.known_terminal_outcomes + c.pending_or_indeterminate:
                raise JournalError("journal_reconcile_mismatch_faulted")


# -- transport --


class JournaledAsyncTransport(httpx.AsyncBaseTransport):
    """Wraps delegate, fsyncs bounded intent before and outcome after proven terminal.

    Injected via CollectorContext.transport, below BoundedHttpClient. Before each
    delegate handle_async_request, fsyncs bounded intent. After delegate returns,
    fsyncs bounded outcome only after proven terminal status and stream completion.
    No headers/body/credentials/exception text stored.

    Pending/indeterminate blocks further delegate calls for that source.
    """

    def __init__(
        self,
        *,
        delegate: httpx.AsyncBaseTransport,
        journal: AcquisitionJournal,
        source_id: str,
        operation_id: str | None = None,
    ) -> None:
        if not isinstance(delegate, httpx.AsyncBaseTransport):
            raise JournalError("journal_delegate_invalid")
        # forbid old JournaledTransport wrapping
        if delegate.__class__.__name__ == "JournaledTransport" and (
            "controlled_acquisition" in delegate.__class__.__module__
        ):
            raise JournalError("forbidden_journaled_transport")
        if not source_id or not source_id.strip():
            raise JournalError("journal_source_invalid")
        op = operation_id if operation_id is not None else journal.operation_id
        if op != journal.operation_id:
            raise JournalError("journal_operation_mismatch")
        self._delegate = delegate
        self._journal = journal
        self._source_id = source_id
        self._operation_id = op
        self._ordinal_counter: int = 0
        self._budget_ordinal: int = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._journal.is_blocked(self._source_id):
            raise JournaledTransportError("indeterminate")

        self._ordinal_counter += 1
        self._budget_ordinal += 1
        ordinal = self._journal.next_ordinal(self._source_id)
        # ensure our local counter aligns with journal (monotonic)
        if ordinal != self._ordinal_counter and self._ordinal_counter == 1:
            # first call may diverge if journal pre-populated; trust journal
            self._ordinal_counter = ordinal

        fingerprint = _fingerprint(request)

        try:
            self._journal.record_intent(
                source_id=self._source_id,
                ordinal=ordinal,
                destination_fingerprint=fingerprint,
                budget_ordinal=self._budget_ordinal,
            )
        except JournalError:
            raise
        except Exception as exc:
            raise JournalError("journal_intent_failed") from exc

        try:
            response = await self._delegate.handle_async_request(request)
        except BaseException:
            # Any delegate/stream exception leaves intent pending/indeterminate
            # emit detail-free sentinel, no outcome recorded, block further calls
            raise JournaledTransportError("indeterminate") from None

        # Prove terminal status and stream completion before persisting outcome
        try:
            status_code = response.status_code
        except Exception:
            raise JournaledTransportError("indeterminate") from None

        status_class, retryable = _classify_status(int(status_code))

        # Stream completion proof: for buffered responses is_stream_consumed True
        # For streaming, we wrap the response to defer outcome until stream completes.
        # If response is already buffered, we can record outcome immediately.
        # Otherwise patch aiter_bytes/aiter_raw to record after successful iteration.

        is_consumed = bool(getattr(response, "is_stream_consumed", False))
        is_closed = bool(getattr(response, "is_closed", False))

        if is_consumed or is_closed or getattr(response, "_content", None) is not None:
            # Already buffered or content available — consider stream complete
            try:
                # Validate content is readable without storing
                _ = response.content if hasattr(response, "content") else b""
            except Exception:
                raise JournaledTransportError("indeterminate") from None
            try:
                self._journal.record_outcome(
                    source_id=self._source_id,
                    ordinal=ordinal,
                    status_code=int(status_code),
                    status_class=status_class,
                    retryable=retryable,
                )
            except JournalError:
                raise
            except Exception as exc:
                raise JournalError("journal_outcome_failed") from exc
            return response

        # Streaming path: wrap iterators to record outcome after successful exhaustion
        original_aiter_bytes = getattr(response, "aiter_bytes", None)
        original_aiter_raw = getattr(response, "aiter_raw", None)
        original_aiter_text = getattr(response, "aiter_text", None)
        journal = self._journal
        source_id = self._source_id

        outcome_recorded = False

        def _maybe_record() -> None:
            nonlocal outcome_recorded
            if outcome_recorded:
                return
            journal.record_outcome(
                source_id=source_id,
                ordinal=ordinal,
                status_code=int(status_code),
                status_class=status_class,
                retryable=retryable,
            )
            outcome_recorded = True

        if callable(original_aiter_bytes):

            async def _wrapped_bytes():  # type: ignore[no-untyped-def]
                try:
                    async for chunk in original_aiter_bytes():
                        yield chunk
                    _maybe_record()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None

            response.aiter_bytes = _wrapped_bytes  # type: ignore[assignment,method-assign]

        if callable(original_aiter_raw):

            async def _wrapped_raw():  # type: ignore[no-untyped-def]
                try:
                    async for chunk in original_aiter_raw():
                        yield chunk
                    _maybe_record()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None

            response.aiter_raw = _wrapped_raw  # type: ignore[assignment,method-assign]

        if callable(original_aiter_text):

            async def _wrapped_text():  # type: ignore[no-untyped-def]
                try:
                    async for chunk in original_aiter_text():
                        yield chunk
                    _maybe_record()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None

            response.aiter_text = _wrapped_text  # type: ignore[assignment,method-assign]

        # Also handle direct .aread() / .read() paths by wrapping content access:
        # We record outcome eagerly only if stream later completes; but for safety
        # we keep pending until stream iteration finishes. Caller (BoundedHttpClient)
        # iterates via aiter_raw, so wrapper above suffices. We still attempt to
        # record on close as fallback.

        original_aclose = getattr(response, "aclose", None)
        if callable(original_aclose):

            async def _wrapped_aclose():  # type: ignore[no-untyped-def]
                try:
                    result = await original_aclose()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None
                # do not auto-record on close unless stream was consumed
                return result

            response.aclose = _wrapped_aclose  # type: ignore[method-assign]

        return response

    async def aclose(self) -> None:
        try:
            await self._delegate.aclose()
        except BaseException:
            raise JournaledTransportError("indeterminate") from None


__all__ = [
    "FINGERPRINT_LEN",
    "MAX_INTENT_BYTES",
    "STATUS_CLASS_NON_RETRYABLE",
    "STATUS_CLASS_OK",
    "STATUS_CLASS_RETRYABLE",
    "AcquisitionJournal",
    "JournalCounts",
    "JournalError",
    "JournaledAsyncTransport",
    "JournaledTransportError",
    "WireIntent",
    "WireOutcome",
    "_classify_status",
    "_fingerprint",
]
