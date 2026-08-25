"""Transport-only adapter for the F10.1F acquisition journal.

The journal owns durable intent/outcome state.  This module owns the HTTPX
transport boundary and records one bounded outcome only after a terminal
response is proven.  It never persists request bodies, headers, credentials,
URLs, or exception text.
"""

from __future__ import annotations

import httpx

from role_radar.evaluation.profile_relevant_acquisition.journal import (
    AcquisitionJournal,
    JournalError,
    _classify_status,
    _fingerprint,
)


class JournaledTransportError(RuntimeError):
    """Detail-free sentinel for an indeterminate wire attempt."""

    def __init__(self, code: str = "indeterminate") -> None:
        self.code = code
        super().__init__(code)


class JournaledAsyncTransport(httpx.AsyncBaseTransport):
    """Wrap a delegate and journal each wire attempt fail-closed."""

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
        self._ordinal_counter = 0
        self._budget_ordinal = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._journal.is_blocked(self._source_id):
            raise JournaledTransportError("indeterminate")

        self._ordinal_counter += 1
        self._budget_ordinal += 1
        ordinal = self._journal.next_ordinal(self._source_id)
        if ordinal != self._ordinal_counter and self._ordinal_counter == 1:
            self._ordinal_counter = ordinal

        try:
            self._journal.record_intent(
                source_id=self._source_id,
                ordinal=ordinal,
                destination_fingerprint=_fingerprint(request),
                budget_ordinal=self._budget_ordinal,
            )
        except JournalError:
            raise
        except Exception as exc:
            raise JournalError("journal_intent_failed") from exc

        try:
            response = await self._delegate.handle_async_request(request)
        except BaseException:
            raise JournaledTransportError("indeterminate") from None

        try:
            status_code = int(response.status_code)
        except Exception:
            raise JournaledTransportError("indeterminate") from None
        status_class, retryable = _classify_status(status_code)

        if (
            bool(getattr(response, "is_stream_consumed", False))
            or bool(getattr(response, "is_closed", False))
            or getattr(response, "_content", None) is not None
        ):
            try:
                _ = response.content if hasattr(response, "content") else b""
                self._journal.record_outcome(
                    source_id=self._source_id,
                    ordinal=ordinal,
                    status_code=status_code,
                    status_class=status_class,
                    retryable=retryable,
                )
            except JournalError:
                raise
            except Exception:
                raise JournaledTransportError("indeterminate") from None
            return response

        original_aiter_bytes = getattr(response, "aiter_bytes", None)
        original_aiter_raw = getattr(response, "aiter_raw", None)
        original_aiter_text = getattr(response, "aiter_text", None)
        journal = self._journal
        source_id = self._source_id
        outcome_recorded = False

        def record_outcome() -> None:
            nonlocal outcome_recorded
            if outcome_recorded:
                return
            journal.record_outcome(
                source_id=source_id,
                ordinal=ordinal,
                status_code=status_code,
                status_class=status_class,
                retryable=retryable,
            )
            outcome_recorded = True

        if callable(original_aiter_bytes):

            async def wrapped_bytes():  # type: ignore[no-untyped-def]
                try:
                    async for chunk in original_aiter_bytes():
                        yield chunk
                    record_outcome()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None

            response.aiter_bytes = wrapped_bytes  # type: ignore[assignment,method-assign]

        if callable(original_aiter_raw):

            async def wrapped_raw():  # type: ignore[no-untyped-def]
                try:
                    async for chunk in original_aiter_raw():
                        yield chunk
                    record_outcome()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None

            response.aiter_raw = wrapped_raw  # type: ignore[assignment,method-assign]

        if callable(original_aiter_text):

            async def wrapped_text():  # type: ignore[no-untyped-def]
                try:
                    async for chunk in original_aiter_text():
                        yield chunk
                    record_outcome()
                except BaseException:
                    raise JournaledTransportError("indeterminate") from None

            response.aiter_text = wrapped_text  # type: ignore[assignment,method-assign]

        return response

    async def aclose(self) -> None:
        try:
            await self._delegate.aclose()
        except BaseException:
            raise JournaledTransportError("indeterminate") from None


__all__ = ["JournaledAsyncTransport", "JournaledTransportError"]
