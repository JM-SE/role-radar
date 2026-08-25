"""Offline intent/outcome and replay coverage for JournaledAsyncTransport."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from role_radar.evaluation.fresh_acquisition.journal import (
    AcquisitionJournal,
    JournaledAsyncTransport,
    JournaledTransportError,
    JournalError,
)


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, *, status_code: int = 200, failure: BaseException | None = None) -> None:
        self.status_code = status_code
        self.failure = failure
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return httpx.Response(self.status_code, request=request, content=b"offline-body")


async def _request(transport: JournaledAsyncTransport) -> httpx.Response:
    return await transport.handle_async_request(
        httpx.Request(
            "POST",
            "https://example.test/v1/jobs?secret-query=do-not-persist",
            headers={"Authorization": "secret-header"},
            content=b"secret-body",
        )
    )


@pytest.mark.asyncio
async def test_transport_durably_records_opaque_intent_and_terminal_outcome(tmp_path: Path) -> None:
    journal = AcquisitionJournal(operation_id="op-journal", root=tmp_path / "private")
    delegate = MockTransport()
    transport = JournaledAsyncTransport(delegate=delegate, journal=journal, source_id="source-a")

    response = await _request(transport)

    assert response.status_code == 200
    assert delegate.calls == 1
    counts = journal.counts("source-a")
    assert counts.durable_intents == counts.known_terminal_outcomes == 1
    assert counts.pending_or_indeterminate == 0
    assert journal.is_sealable("source-a")
    journal.reconcile_equations("source-a")
    persisted = (tmp_path / "private" / "journal" / "op-journal.jsonl").read_bytes()
    assert b"secret-query" not in persisted
    assert b"secret-header" not in persisted
    assert b"secret-body" not in persisted
    assert b"destination_fingerprint" in persisted


@pytest.mark.asyncio
async def test_known_retryable_outcome_allows_retry_but_not_pending(tmp_path: Path) -> None:
    journal = AcquisitionJournal(operation_id="op-retry", root=tmp_path / "private")
    delegate = MockTransport(status_code=503)
    transport = JournaledAsyncTransport(delegate=delegate, journal=journal, source_id="source-a")

    await _request(transport)

    assert delegate.calls == 1
    assert journal.can_retry("source-a")
    assert journal.should_skip_source("source-a", checkpoint_wire_attempts=1)
    journal.reconcile_equations("source-a")

    failing_journal = AcquisitionJournal(operation_id="op-pending", root=tmp_path / "pending")
    failing_delegate = MockTransport(failure=RuntimeError("raw exception must not escape"))
    failing = JournaledAsyncTransport(
        delegate=failing_delegate,
        journal=failing_journal,
        source_id="source-a",
    )
    with pytest.raises(JournaledTransportError) as indeterminate:
        await _request(failing)
    assert indeterminate.value.code == "indeterminate"
    assert failing_journal.pending_count("source-a") == 1
    assert not failing_journal.can_retry("source-a")
    assert not failing_journal.should_skip_source("source-a", checkpoint_wire_attempts=1)

    with pytest.raises(JournaledTransportError):
        await _request(failing)
    assert failing_delegate.calls == 1
    failing_journal.reconcile_equations("source-a")


def test_journal_rejects_new_intent_while_source_is_pending(tmp_path: Path) -> None:
    journal = AcquisitionJournal(operation_id="op", root=tmp_path / "private")
    journal.record_intent(
        source_id="source-a",
        ordinal=1,
        destination_fingerprint="a" * 16,
        budget_ordinal=1,
    )
    with pytest.raises(JournalError) as exc:
        journal.record_intent(
            source_id="source-a",
            ordinal=2,
            destination_fingerprint="b" * 16,
            budget_ordinal=2,
        )
    assert exc.value.code == "journal_source_blocked_pending"
    counts = journal.counts("source-a")
    assert counts.durable_intents == (
        counts.known_terminal_outcomes + counts.pending_or_indeterminate
    )
