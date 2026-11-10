from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from role_radar.domain.enums import JobSearchRunStatus
from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository
from role_radar.worker.runner import WorkerRunner


def test_claim_run_selects_only_the_requested_run_without_failing_another_stale_run(
    db_session,
) -> None:
    repository = RunRepository(db_session)
    unrelated = repository.create_run("unrelated")
    selected = repository.create_run("canary")
    selected.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()

    claimed = repository.claim_run(
        selected.id,
        worker_id="canary-worker",
        now=datetime.now(UTC),
        max_recoveries=0,
    )
    db_session.commit()

    assert claimed is not None
    assert claimed.id == selected.id
    assert unrelated.status is JobSearchRunStatus.PENDING
    assert unrelated.claimed_by is None


def test_claim_run_uses_existing_recovery_cas_for_selected_run(db_session) -> None:
    repository = RunRepository(db_session)
    run = repository.create_run("canary")
    run.status = JobSearchRunStatus.COLLECTING
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.recovery_count = 0
    run.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    claimed = repository.claim_run(
        run.id,
        worker_id="canary-worker",
        now=datetime.now(UTC),
        max_recoveries=1,
    )
    db_session.commit()

    assert claimed is not None
    assert claimed.id == run.id
    assert claimed.claimed_by == "canary-worker"
    assert claimed.recovery_count == 1


def test_deferred_canary_is_not_claimed_by_normal_worker_and_exact_resume_preserves_counts(
    db_session,
) -> None:
    repository = RunRepository(db_session)
    run = repository.create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.status = JobSearchRunStatus.DEFERRED
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "extraction",
        "cursor": 1,
        "counts": {"broker_calls": 2},
        "reservations": [],
    }
    db_session.commit()
    run_id = run.id

    assert repository.claim_next(worker_id="normal-worker") is None
    claimed = repository.claim_run(run_id, worker_id="canary-worker")

    assert claimed is not None
    assert claimed.canary_checkpoint_json["stage"] == "extraction"
    assert claimed.canary_checkpoint_json["cursor"] == 1
    assert claimed.canary_checkpoint_json["counts"]["broker_calls"] == 2


def test_exact_claim_refuses_a_normal_run(db_session) -> None:
    run = RunRepository(db_session).create_run("ordinary")
    db_session.commit()

    assert RunRepository(db_session).claim_run(run.id, worker_id="canary-worker") is None
    assert run.status is JobSearchRunStatus.PENDING


def test_normal_claim_skips_pending_canary_and_claims_ordinary(db_session) -> None:
    repository = RunRepository(db_session)
    canary = repository.create_run("canary")
    canary.canary_budget_json = dict(CANARY_BUDGET)
    ordinary = repository.create_run("ordinary")
    db_session.commit()

    claimed = repository.claim_next(worker_id="normal-worker")
    assert claimed is not None and claimed.id == ordinary.id
    assert canary.claimed_by is None
    assert canary.status is JobSearchRunStatus.PENDING


def test_normal_claim_never_terminalizes_exhausted_canary(db_session) -> None:
    repository = RunRepository(db_session)
    canary = repository.create_run("canary")
    canary.canary_budget_json = dict(CANARY_BUDGET)
    canary.status = JobSearchRunStatus.COLLECTING
    canary.recovery_count = 5
    canary.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    assert repository.claim_next(worker_id="normal-worker") is None
    assert canary.status is JobSearchRunStatus.COLLECTING
    assert canary.error_code is None


def test_normal_claim_accepts_json_null_as_no_canary_budget(db_session) -> None:
    repository = RunRepository(db_session)
    run = repository.create_run("ordinary-json-null")
    db_session.flush()
    db_session.execute(
        text("UPDATE job_search_runs SET canary_budget_json='null' WHERE id=:run_id"),
        {"run_id": run.id},
    )
    db_session.commit()
    assert repository.claim_run(run.id, worker_id="canary-worker") is None

    claimed = repository.claim_next(worker_id="normal-worker")
    assert claimed is not None and claimed.id == run.id


def test_one_shot_runner_processes_only_exact_run(db_session, settings) -> None:
    repository = RunRepository(db_session)
    unrelated = repository.create_run("unrelated")
    selected = repository.create_run("canary")
    selected.canary_budget_json = dict(CANARY_BUDGET)
    db_session.commit()
    unrelated_id, selected_id = unrelated.id, selected.id

    class Pipeline:
        def __init__(self) -> None:
            self.processed: list[str] = []

        async def run(self, run_id: str) -> None:
            self.processed.append(run_id)

    pipeline = Pipeline()
    runner = WorkerRunner(lambda: db_session, pipeline, settings=settings)

    assert runner.run_once(run_id=selected_id) is True
    assert pipeline.processed == [selected_id]
    with db_session:
        unchanged = db_session.get(type(unrelated), unrelated_id)
        assert unchanged.status is JobSearchRunStatus.PENDING
        assert unchanged.claimed_by is None
