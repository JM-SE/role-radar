import asyncio

from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository
from tests.integration._canary_pipeline_support import _resumable_pipeline


def test_pipeline_deferral_preserves_stage_and_consumed_budget(db_session) -> None:
    from role_radar.domain.enums import JobSearchRunStatus
    from role_radar.worker.pipeline import Pipeline

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "deep_evaluation",
        "cursor": 1,
        "counts": {"broker_calls": 3, "broker_attempts": 3},
        "reservations": [],
        "logical_reservations": [],
    }
    db_session.commit()
    run_id = run.id
    pipeline = Pipeline.__new__(Pipeline)
    pipeline._session_factory = lambda: db_session

    pipeline._defer_canary(run_id, "canary_budget_exhausted:broker_attempts")

    db_session.expire_all()
    deferred = db_session.get(type(run), run_id)
    assert deferred.status is JobSearchRunStatus.DEFERRED
    assert deferred.canary_checkpoint_json["stage"] == "deep_evaluation"
    assert deferred.canary_checkpoint_json["cursor"] == 1
    assert deferred.canary_checkpoint_json["counts"]["broker_calls"] == 3
    assert deferred.completed_at is None

def test_pipeline_run_resumes_extraction_at_checkpoint_without_replaying_producers(
    db_session,
) -> None:
    from role_radar.db.models import Job, JobSearchRun, RunJob
    from role_radar.domain.enums import (
        ExtractionStatus,
        JobSearchRunStatus,
        RunJobStage,
        RunJobStatus,
    )

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.status = JobSearchRunStatus.DEFERRED
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "extraction",
        "cursor": 1,
        "counts": {"broker_calls": 2, "broker_attempts": 2},
        "reservations": [],
        "logical_reservations": [],
    }
    for job_id in ("job-a", "job-b"):
        db_session.add(Job(id=job_id, title="Engineer", company="Acme"))
        db_session.add(
            RunJob(
                run_id=run.id,
                job_id=job_id,
                stage=RunJobStage.DEDUPLICATED,
                status=RunJobStatus.SUCCEEDED,
            )
        )
    db_session.add(
        RunJob(
            run_id=run.id,
            job_id="job-a",
            stage=RunJobStage.EXTRACTED,
            status=RunJobStatus.SUCCEEDED,
        )
    )
    db_session.commit()
    run_id = run.id

    class Extraction:
        def __init__(self):
            self.prepared = []

        def prepare(self, job_id):
            self.prepared.append(job_id)
            return job_id

        async def execute(self, prepared):
            return prepared

        def finalize(self, execution):
            return type(
                "Finalized",
                (),
                {"status": ExtractionStatus.VALID, "retry_corrective": False},
            )()

    class Notifications:
        async def process(self, *_args, **_kwargs):
            return ()

    extraction = Extraction()
    pipeline = _resumable_pipeline(
        db_session,
        extraction=extraction,
        notifications=Notifications(),
        stage="extraction",
    )
    pipeline._extraction = extraction

    asyncio.run(pipeline.run(run_id))
    db_session.expire_all()
    completed = db_session.get(JobSearchRun, run_id)

    assert extraction.prepared == ["job-b"]
    assert pipeline._scoring.calls == 1
    assert completed.status is JobSearchRunStatus.COMPLETED
    assert completed.canary_checkpoint_json["stage"] == "complete"
    assert completed.canary_checkpoint_json["counts"]["broker_calls"] == 2
    assert completed.canary_checkpoint_json["counts"]["broker_attempts"] == 2

def test_pipeline_run_resumes_scoring_without_replaying_extraction(db_session) -> None:
    from role_radar.db.models import Job, JobSearchRun, RunJob
    from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.status = JobSearchRunStatus.DEFERRED
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "scoring",
        "cursor": 0,
        "counts": {"broker_calls": 3, "broker_attempts": 3},
        "reservations": [],
        "logical_reservations": [],
    }
    db_session.add(Job(id="job-scoring", title="Engineer", company="Acme"))
    db_session.add_all(
        [
            RunJob(
                run_id=run.id,
                job_id="job-scoring",
                stage=RunJobStage.DEDUPLICATED,
                status=RunJobStatus.SUCCEEDED,
            ),
            RunJob(
                run_id=run.id,
                job_id="job-scoring",
                stage=RunJobStage.EXTRACTED,
                status=RunJobStatus.FAILED,
            ),
        ]
    )
    db_session.commit()
    run_id = run.id

    class Extraction:
        def __init__(self):
            self.prepared = []

        def prepare(self, job_id):
            self.prepared.append(job_id)
            return None

    extraction = Extraction()
    pipeline = _resumable_pipeline(db_session, extraction=extraction, stage="scoring")
    pipeline._extraction = extraction
    asyncio.run(pipeline.run(run_id))
    db_session.expire_all()
    completed = db_session.get(JobSearchRun, run_id)

    assert extraction.prepared == []
    assert pipeline._scoring.calls == 1
    assert completed.status is JobSearchRunStatus.COMPLETED
    assert completed.canary_checkpoint_json["counts"]["broker_calls"] == 3
    assert completed.canary_checkpoint_json["counts"]["broker_attempts"] == 3

def test_pipeline_run_resumes_deep_evaluation_without_replaying_collection(db_session) -> None:
    from role_radar.db.models import Job, RunJob
    from role_radar.domain.enums import JobSearchRunStatus, RunJobStage, RunJobStatus

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.status = JobSearchRunStatus.DEFERRED
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "deep_evaluation",
        "cursor": 0,
        "counts": {"broker_calls": 3, "broker_attempts": 3},
        "reservations": [],
        "logical_reservations": [],
    }
    db_session.add(Job(id="job-deep", title="Engineer", company="Acme"))
    db_session.add_all(
        [
            RunJob(
                run_id=run.id,
                job_id="job-deep",
                stage=RunJobStage.DEDUPLICATED,
                status=RunJobStatus.SUCCEEDED,
            ),
            RunJob(
                run_id=run.id,
                job_id="job-deep",
                stage=RunJobStage.EXTRACTED,
                status=RunJobStatus.FAILED,
            ),
        ]
    )
    db_session.commit()
    run_id = run.id

    class Extraction:
        def __init__(self):
            self.prepared = []

        def prepare(self, job_id):
            self.prepared.append(job_id)
            return None

    class Deep:
        prepared = 0
        processed = 0

        def prepare_queue(self, _run_id, _job_ids):
            self.prepared += 1

        async def process(self, _run_id):
            self.processed += 1

    deep = Deep()
    extraction = Extraction()
    pipeline = _resumable_pipeline(
        db_session,
        extraction=extraction,
        deep=deep,
        stage="deep_evaluation",
    )
    pipeline._extraction = extraction
    asyncio.run(pipeline.run(run_id))

    assert extraction.prepared == []
    assert deep.prepared == 0
    assert deep.processed == 1
    assert pipeline._scoring.calls == 0
    resumed = db_session.get(type(run), run_id)
    assert resumed.status is JobSearchRunStatus.COMPLETED
    assert resumed.canary_checkpoint_json["counts"]["broker_calls"] == 3
    assert resumed.canary_checkpoint_json["counts"]["broker_attempts"] == 3

def test_pipeline_run_resumes_notifications_without_replaying_producers(db_session) -> None:
    from role_radar.domain.enums import JobSearchRunStatus, NotificationMode

    run = RunRepository(db_session).create_run("canary", notification_mode="match_alerts")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.status = JobSearchRunStatus.DEFERRED
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "notifications",
        "cursor": 0,
        "counts": {"broker_calls": 4, "broker_attempts": 4},
        "reservations": [],
        "logical_reservations": [],
    }
    run.notification_mode = NotificationMode.MATCH_ALERTS
    db_session.commit()
    run_id = run.id

    class Deep:
        prepare_calls = 0
        process_calls = 0

        def prepare_queue(self, *_args, **_kwargs):
            self.prepare_calls += 1

        async def process(self, *_args, **_kwargs):
            self.process_calls += 1

    class Notifications:
        calls = 0

        async def process(self, *_args, **_kwargs):
            self.calls += 1
            return ()

    notifications = Notifications()
    deep = Deep()
    pipeline = _resumable_pipeline(
        db_session, deep=deep, notifications=notifications, stage="notifications"
    )
    asyncio.run(pipeline.run(run_id))

    assert notifications.calls == 1
    assert deep.prepare_calls == 0
    assert deep.process_calls == 0
    assert pipeline._scoring.calls == 0
    resumed = db_session.get(type(run), run_id)
    assert resumed.status is JobSearchRunStatus.COMPLETED
    assert resumed.canary_checkpoint_json["stage"] == "complete"
    assert resumed.canary_checkpoint_json["counts"]["broker_calls"] == 4
    assert resumed.canary_checkpoint_json["counts"]["broker_attempts"] == 4
