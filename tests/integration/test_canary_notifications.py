from role_radar.domain.enums import JobSearchRunStatus
from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository


def test_canary_notification_prepare_creates_only_one_batch(
    db_session, settings, monkeypatch
) -> None:
    from datetime import UTC, datetime

    from role_radar.db.models import NotificationBatch
    from role_radar.domain.enums import NotificationMode
    from role_radar.notifications.contracts import DigestCandidate
    from role_radar.repositories.jobs import JobRepository
    from role_radar.services.notification_service import NotificationService

    run = RunRepository(db_session).create_run("canary")
    run.status = JobSearchRunStatus.NOTIFYING
    run.notification_mode = NotificationMode.MATCH_ALERTS
    run.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    run_id = run.id
    candidates = [
        DigestCandidate(
            job_id=f"job-{index}",
            job_score_id=f"score-{index}",
            deep_evaluation_id=None,
            title=f"Engineer {index}",
            company=f"Company {index}",
            location="Remote",
            application_url=f"https://example.test/jobs/{index}",
            final_score=90 - index,
            preliminary_score=80 - index,
            first_seen_at=datetime.now(UTC),
        )
        for index in range(6)
    ]
    monkeypatch.setattr(
        JobRepository,
        "list_delivery_candidates",
        lambda *_args, **_kwargs: candidates,
    )

    batches = NotificationService(lambda: db_session, settings=settings).prepare(
        run_id, recipient_key="canary-recipient"
    )

    assert len(batches) == 1
    assert batches[0].item_count == 5
    assert len(db_session.query(NotificationBatch).filter_by(run_id=run_id).all()) == 1
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["counts"]["notification_batches"] == 1

def test_canary_stale_recovery_does_not_mutate_other_runs(db_session, settings) -> None:
    import asyncio
    from datetime import UTC, datetime, timedelta

    from role_radar.db.models import NotificationBatch
    from role_radar.domain.enums import NotificationBatchStatus
    from role_radar.services.notification_service import NotificationService

    canary = RunRepository(db_session).create_run("canary")
    canary.canary_budget_json = dict(CANARY_BUDGET)
    unrelated = RunRepository(db_session).create_run("ordinary")
    started = datetime.now(UTC) - timedelta(hours=1)

    def batch(run_id: str, operation_key: str) -> NotificationBatch:
        return NotificationBatch(
            run_id=run_id,
            schedule_slot="manual",
            channel="telegram",
            recipient_key_hash="d" * 64,
            operation_key=operation_key,
            fingerprint="e" * 64,
            formatter_version="test-v1",
            status=NotificationBatchStatus.SENDING,
            body="reserved",
            body_hash="f" * 64,
            body_length=8,
            item_count=1,
            attempt_count=1,
            sending_started_at=started,
        )

    canary_batch = batch(canary.id, "canary-stale")
    unrelated_batch = batch(unrelated.id, "ordinary-stale")
    db_session.add_all([canary_batch, unrelated_batch])
    db_session.commit()
    canary_id, other_batch_id = canary.id, unrelated_batch.id
    db_session.expunge_all()

    class Gateway:
        async def send_message(self, _request):
            raise AssertionError("no prepared canary notification exists")

    asyncio.run(
        NotificationService(lambda: db_session, settings=settings).process(
            canary_id, recipient_key="canary-recipient", gateway=Gateway()
        )
    )

    db_session.expire_all()
    unrelated_batch = db_session.get(NotificationBatch, other_batch_id)
    assert unrelated_batch.status is NotificationBatchStatus.SENDING

def test_canary_unknown_telegram_delivery_is_not_replayed(db_session, settings) -> None:
    import asyncio

    from role_radar.db.models import NotificationBatch
    from role_radar.domain.enums import NotificationBatchStatus
    from role_radar.notifications.contracts import Indeterminate
    from role_radar.services.notification_service import NotificationService

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    batch = NotificationBatch(
        run_id=run.id,
        schedule_slot="manual",
        channel="telegram",
        recipient_key_hash="a" * 64,
        operation_key="canary:one",
        fingerprint="b" * 64,
        formatter_version="test-v1",
        status=NotificationBatchStatus.PREPARED,
        body="bounded message",
        body_hash="c" * 64,
        body_length=15,
        item_count=1,
    )
    db_session.add(batch)
    db_session.commit()
    run_id, batch_id = run.id, batch.id

    class Gateway:
        calls = 0

        async def send_message(self, _request):
            self.calls += 1
            return Indeterminate(code="timeout")

    gateway = Gateway()
    service = NotificationService(lambda: db_session, settings=settings)

    async def deliver_twice() -> None:
        await service.deliver(batch_id, gateway)
        await service.deliver(batch_id, gateway)

    asyncio.run(deliver_twice())
    db_session.expire_all()
    persisted = db_session.get(NotificationBatch, batch_id)
    assert persisted.status is NotificationBatchStatus.UNKNOWN
    assert persisted.attempt_count == 1
    assert gateway.calls == 1
    assert db_session.get(type(run), run_id).status is JobSearchRunStatus.PENDING
