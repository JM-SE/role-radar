from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.config import Settings
from role_radar.db.base import Base
from role_radar.db.engine import get_engine
from role_radar.db.models import JobSearchRun, NotificationBatch
from role_radar.domain.enums import (
    JobSearchRunStatus,
    NotificationBatchStatus,
    NotificationMode,
)
from role_radar.notifications.contracts import (
    Accepted,
    Indeterminate,
    TelegramDeliveryResult,
    TelegramSendRequest,
)
from role_radar.notifications.formatter import (
    FORMATTER_VERSION,
    LEGACY_DIGEST_FORMATTER_VERSION,
)
from role_radar.repositories.notification_batches import NotificationBatchRepository
from role_radar.services.notification_service import NotificationService, recipient_key_hash
from role_radar.worker.pipeline import Pipeline


class CountingGateway:
    def __init__(self, result: TelegramDeliveryResult) -> None:
        self.result = result
        self.requests: list[TelegramSendRequest] = []

    async def send_message(self, request: TelegramSendRequest) -> TelegramDeliveryResult:
        self.requests.append(request)
        return self.result


@pytest.fixture
def file_session_factory(tmp_path: Path) -> Iterator[Callable[[], Session]]:
    database_path = tmp_path / "phase07-recovery.db"
    engine = get_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)

    def factory() -> Session:
        return Session(engine)

    yield factory
    engine.dispose()


def _create_prepared_batch(
    session_factory: Callable[[], Session], *, recipient_hash: str = "r" * 64
) -> tuple[str, str]:
    with session_factory() as session:
        run = JobSearchRun(
            reason="phase07-recovery",
            status=JobSearchRunStatus.NOTIFYING,
            notification_mode=NotificationMode.DAILY_DIGEST,
        )
        session.add(run)
        session.flush()
        batch = NotificationBatch(
            run_id=run.id,
            schedule_slot="manual",
            channel="telegram",
            recipient_key_hash=recipient_hash,
            operation_key=f"{run.id}:manual:telegram:{recipient_hash}:{FORMATTER_VERSION}",
            fingerprint="f" * 64,
            formatter_version=FORMATTER_VERSION,
            status=NotificationBatchStatus.PREPARED,
            body="<b>digest</b>",
            body_hash="b" * 64,
            body_length=13,
            item_count=1,
        )
        session.add(batch)
        session.commit()
        return run.id, batch.id


def _claim_batch(
    session_factory: Callable[[], Session], batch_id: str, started_at: datetime
) -> str:
    with session_factory() as session:
        batch = NotificationBatchRepository(session).claim_sending(
            batch_id, max_attempts=3, now=started_at
        )
        assert batch is not None
        session.commit()
        return str(batch.body or "")


def _recover_stale(session_factory: Callable[[], Session], now: datetime) -> None:
    with session_factory() as session:
        recovered = NotificationBatchRepository(session).recover_stale(
            older_than=timedelta(seconds=0), now=now
        )
        assert recovered == 1
        session.commit()


@pytest.mark.asyncio
async def test_replay_after_sent_does_not_post_again(
    file_session_factory: Callable[[], Session],
) -> None:
    _, batch_id = _create_prepared_batch(file_session_factory)
    gateway = CountingGateway(Accepted(message_id=42))
    service = NotificationService(
        file_session_factory,
        settings=Settings(environment="dev", telegram_max_attempts=3),
    )

    first = await service.deliver(batch_id, gateway)
    second = await service.deliver(batch_id, gateway)

    assert first is not None
    assert second is not None
    assert len(gateway.requests) == 1
    with file_session_factory() as session:
        persisted = session.get(NotificationBatch, batch_id)
        assert persisted is not None
        assert persisted.status is NotificationBatchStatus.SENT
        assert persisted.body is None
        assert persisted.telegram_message_id == 42


@pytest.mark.asyncio
async def test_stale_sending_becomes_unknown_without_second_post(
    file_session_factory: Callable[[], Session],
) -> None:
    _, batch_id = _create_prepared_batch(file_session_factory)
    started_at = datetime.now(UTC) - timedelta(minutes=1)
    body = _claim_batch(file_session_factory, batch_id, started_at)

    gateway = CountingGateway(Indeterminate(code="read_timeout"))
    await gateway.send_message(TelegramSendRequest(body=body))
    _recover_stale(file_session_factory, datetime.now(UTC))

    service = NotificationService(
        file_session_factory,
        settings=Settings(environment="dev", telegram_max_attempts=3),
    )
    recovered = await service.deliver(batch_id, gateway)

    assert recovered is not None and recovered.status is NotificationBatchStatus.UNKNOWN
    assert len(gateway.requests) == 1
    with file_session_factory() as session:
        persisted = session.scalar(
            select(NotificationBatch).where(NotificationBatch.id == batch_id)
        )
        assert persisted is not None
        assert persisted.body is None
        assert persisted.error_code == "stale_sending"


@pytest.mark.asyncio
async def test_legacy_v1_retry_wait_batch_is_reused_after_upgrade(
    file_session_factory: Callable[[], Session],
) -> None:
    recipient = "legacy-digest-recipient"
    recipient_hash = recipient_key_hash(recipient)
    with file_session_factory() as session:
        run = JobSearchRun(
            reason="legacy-digest-recovery",
            status=JobSearchRunStatus.NOTIFYING,
            notification_mode=NotificationMode.DAILY_DIGEST,
        )
        session.add(run)
        session.flush()
        batch = NotificationBatch(
            run_id=run.id,
            schedule_slot="manual",
            channel="telegram",
            recipient_key_hash=recipient_hash,
            operation_key=(
                f"{run.id}:manual:telegram:{recipient_hash}:"
                f"{LEGACY_DIGEST_FORMATTER_VERSION}"
            ),
            fingerprint="a" * 64,
            formatter_version=LEGACY_DIGEST_FORMATTER_VERSION,
            status=NotificationBatchStatus.RETRY_WAIT,
            body="<b>old digest body</b>",
            body_hash="c" * 64,
            body_length=22,
            item_count=1,
            attempt_count=1,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        session.add(batch)
        session.commit()
        run_id, batch_id = run.id, batch.id

    gateway = CountingGateway(Accepted(message_id=43))
    service = NotificationService(
        file_session_factory,
        settings=Settings(environment="dev", telegram_max_attempts=3),
    )

    outcomes = await service.process(run_id, recipient_key=recipient, gateway=gateway)

    assert len(outcomes) == 1
    assert outcomes[0].id == batch_id
    assert outcomes[0].status is NotificationBatchStatus.SENT
    assert len(gateway.requests) == 1
    assert gateway.requests[0].body == "<b>old digest body</b>"
    with file_session_factory() as session:
        batches = list(
            session.scalars(
                select(NotificationBatch).where(NotificationBatch.run_id == run_id)
            )
        )
        assert len(batches) == 1


@pytest.mark.asyncio
async def test_current_digest_namespace_takes_precedence_over_legacy_retry(
    file_session_factory: Callable[[], Session],
) -> None:
    recipient = "mixed-version-recipient"
    recipient_hash = recipient_key_hash(recipient)
    with file_session_factory() as session:
        run = JobSearchRun(
            reason="mixed-digest-recovery",
            status=JobSearchRunStatus.NOTIFYING,
            notification_mode=NotificationMode.DAILY_DIGEST,
        )
        session.add(run)
        session.flush()
        current = NotificationBatch(
            run_id=run.id,
            schedule_slot="manual",
            channel="telegram",
            recipient_key_hash=recipient_hash,
            operation_key=(
                f"{run.id}:manual:telegram:{recipient_hash}:"
                f"{FORMATTER_VERSION}:part:0001"
            ),
            fingerprint="d" * 64,
            formatter_version=FORMATTER_VERSION,
            status=NotificationBatchStatus.SENT,
            body=None,
            body_hash="e" * 64,
            body_length=12,
            item_count=1,
        )
        legacy = NotificationBatch(
            run_id=run.id,
            schedule_slot="manual",
            channel="telegram",
            recipient_key_hash=recipient_hash,
            operation_key=(
                f"{run.id}:manual:telegram:{recipient_hash}:"
                f"{LEGACY_DIGEST_FORMATTER_VERSION}"
            ),
            fingerprint="f" * 64,
            formatter_version=LEGACY_DIGEST_FORMATTER_VERSION,
            status=NotificationBatchStatus.RETRY_WAIT,
            body="<b>older retry</b>",
            body_hash="1" * 64,
            body_length=20,
            item_count=1,
            attempt_count=1,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        session.add_all((current, legacy))
        session.commit()
        run_id, current_id, legacy_id = run.id, current.id, legacy.id

    gateway = CountingGateway(Accepted(message_id=44))
    service = NotificationService(
        file_session_factory,
        settings=Settings(environment="dev", telegram_max_attempts=3),
    )

    outcomes = await service.process(run_id, recipient_key=recipient, gateway=gateway)

    assert [batch.id for batch in outcomes] == [current_id]
    assert gateway.requests == []
    with file_session_factory() as session:
        old_retry = session.get(NotificationBatch, legacy_id)
        assert old_retry is not None
        assert old_retry.status is NotificationBatchStatus.RETRY_WAIT


@pytest.mark.asyncio
async def test_pipeline_notification_stage_completes_file_backed(
    file_session_factory: Callable[[], Session],
) -> None:
    recipient = "phase07-test-chat"
    run_id, batch_id = _create_prepared_batch(
        file_session_factory, recipient_hash=recipient_key_hash(recipient)
    )
    gateway = CountingGateway(Accepted(message_id=7))
    pipeline = Pipeline(
        file_session_factory,
        provider=FakeLLMProvider(),
        notification_gateway=gateway,
        notification_recipient=recipient,
    )

    result = await pipeline.run(run_id)

    assert result is not None
    assert len(gateway.requests) == 1
    with file_session_factory() as session:
        completed = session.get(JobSearchRun, run_id)
        assert completed is not None
        assert completed.status is JobSearchRunStatus.COMPLETED
        persisted = session.get(NotificationBatch, batch_id)
        assert persisted is not None
        assert persisted.status is NotificationBatchStatus.SENT
