import asyncio

from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository
from tests.integration._canary_pipeline_support import (
    _assert_stage_deferred,
    _new_deferred_stage_run,
    _resumable_pipeline,
    _stage_pipeline_with_hooks,
)


def test_pipeline_run_defers_and_retries_discovery_without_exceeding_source_cap(db_session) -> None:
    from role_radar.domain.enums import DiscoveryMode, JobSearchRunStatus
    from role_radar.execution_budget import reserve_network_attempt, settle_network_attempt

    run = RunRepository(db_session).create_run(
        "canary", discovery_mode=DiscoveryMode.SCHEDULED_DUE
    )
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "discovery",
        "cursor": 0,
        "counts": {},
        "reservations": [],
        "logical_reservations": [],
    }
    db_session.commit()
    run_id = run.id

    class Discovery:
        prepared = 0
        executions = 0
        network_calls = 0

        def prepare(self, _run_id):
            self.prepared += 1
            return object()

        async def execute(self, _plan):
            self.executions += 1
            if self.network_calls == 0:
                for _ in range(2):
                    token = reserve_network_attempt()
                    self.network_calls += 1
                    settle_network_attempt(token)
            token = reserve_network_attempt()
            self.network_calls += 1
            settle_network_attempt(token)
            raise AssertionError("the source cap should defer before this point")

        def finalize(self, _execution):
            raise AssertionError("incomplete discovery must not be finalized")

    pipeline = _resumable_pipeline(db_session, stage="discovery")
    discovery = Discovery()
    pipeline._discovery = discovery

    asyncio.run(pipeline.run(run_id))
    db_session.expire_all()
    first = db_session.get(type(run), run_id)
    assert first.status is JobSearchRunStatus.DEFERRED
    assert discovery.network_calls == 2
    assert first.canary_checkpoint_json["counts"]["source_http_attempts"] == 2

    asyncio.run(pipeline.run(run_id))
    db_session.expire_all()
    second = db_session.get(type(run), run_id)
    assert second.status is JobSearchRunStatus.DEFERRED
    assert discovery.prepared == 2
    assert discovery.network_calls == 2
    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.canary_checkpoint_json["stage"] == "discovery"
    assert persisted.canary_checkpoint_json["counts"]["source_http_attempts"] == 2




def test_pipeline_defers_at_extraction_then_retries_only_extraction(db_session) -> None:
    from types import SimpleNamespace

    from role_radar.domain.enums import ExtractionStatus
    from role_radar.execution_budget import reserve_network_attempt

    class Extraction:
        def __init__(self):
            self.prepare_calls = 0
            self.execute_calls = 0
            self.prepared = []

        def prepare(self, job_id):
            self.prepare_calls += 1
            self.prepared.append(job_id)
            return job_id

        async def execute(self, _prepared):
            self.execute_calls += 1
            reserve_network_attempt("broker_attempts")
            raise AssertionError("the exhausted attempt ceiling must block before I/O")

        def finalize(self, _execution):
            return SimpleNamespace(status=ExtractionStatus.VALID, retry_corrective=False)

    class Scoring:
        calls = 0

        def score(self, _run_id, _job_ids):
            self.calls += 1

    class Notifications:
        async def process(self, *_args, **_kwargs):
            return ()

    run_id = _new_deferred_stage_run(
        db_session,
        prior_completed=True,
        counts={"broker_calls": 1, "broker_attempts": 4},
    )
    extraction = Extraction()
    scoring = Scoring()
    pipeline = _stage_pipeline_with_hooks(
        db_session,
        extraction=extraction,
        scoring=scoring,
        deep=None,
        notifications=Notifications(),
    )

    counts = {"broker_calls": 1, "broker_attempts": 4}
    asyncio.run(pipeline.run(run_id))
    _assert_stage_deferred(
        db_session, run_id, stage="extraction", cursor=1, counts=counts
    )
    asyncio.run(pipeline.run(run_id))

    _assert_stage_deferred(
        db_session, run_id, stage="extraction", cursor=1, counts=counts
    )
    assert extraction.execute_calls == 2
    assert extraction.prepared == ["stage-job", "stage-job"]
    assert scoring.calls == 0
    assert pipeline._discovery.prepare_calls == 1
    assert pipeline._collection.calls == 0

def test_pipeline_scoring_failure_is_recorded_and_continues_without_deferring(db_session) -> None:
    from sqlalchemy import select

    from role_radar.db.models import JobSearchRun, RunJob
    from role_radar.domain.enums import (
        ExtractionStatus,
        JobSearchRunStatus,
        RunJobStage,
        RunJobStatus,
    )
    from role_radar.services.pipeline_scoring import PipelineScoringService

    class Extraction:
        def prepare(self, job_id):
            return job_id

        async def execute(self, _prepared):
            return object()

        def finalize(self, _execution):
            return type(
                "Finalized",
                (),
                {"status": ExtractionStatus.VALID, "retry_corrective": False},
            )()

    class Deep:
        process_calls = 0

        def prepare_queue(self, _run_id, _job_ids):
            pass

        async def process(self, _run_id):
            self.process_calls += 1

    class Notifications:
        async def process(self, *_args, **_kwargs):
            return ()

    run_id = _new_deferred_stage_run(db_session)
    deep = Deep()
    pipeline = _stage_pipeline_with_hooks(
        db_session,
        extraction=Extraction(),
        scoring=None,
        deep=deep,
        notifications=Notifications(),
    )
    pipeline._scoring = PipelineScoringService(lambda: db_session)

    asyncio.run(pipeline.run(run_id))
    db_session.expire_all()
    run = db_session.get(JobSearchRun, run_id)
    scored = db_session.scalar(
        select(RunJob).where(
            RunJob.run_id == run_id,
            RunJob.job_id == "stage-job",
            RunJob.stage == RunJobStage.SCORED,
        )
    )

    assert run.status is JobSearchRunStatus.COMPLETED
    assert scored.status is RunJobStatus.FAILED
    assert scored.error_code == "profile_missing"
    assert deep.process_calls == 1
    assert pipeline._discovery.prepare_calls == 1
    assert pipeline._collection.calls == 0
    assert run.canary_checkpoint_json["stage"] == "complete"
    assert run.canary_checkpoint_json["counts"] == {
        "broker_calls": 1,
        "broker_attempts": 2,
    }

def test_pipeline_defers_at_deep_evaluation_then_retries_without_scoring(db_session) -> None:
    from role_radar.domain.enums import ExtractionStatus, JobSearchRunStatus
    from role_radar.execution_budget import reserve_logical_call

    class Extraction:
        execute_calls = 0

        def prepare(self, job_id):
            return job_id

        async def execute(self, _prepared):
            self.execute_calls += 1
            return object()

        def finalize(self, _execution):
            return type(
                "Finalized",
                (),
                {"status": ExtractionStatus.VALID, "retry_corrective": False},
            )()

    class Scoring:
        calls = 0

        def score(self, _run_id, _job_ids):
            self.calls += 1

    class Deep:
        prepare_calls = 0
        process_calls = 0

        def prepare_queue(self, _run_id, _job_ids):
            self.prepare_calls += 1

        async def process(self, _run_id):
            self.process_calls += 1
            reserve_logical_call("broker_calls")
            raise AssertionError("the exhausted logical-call ceiling must block before I/O")

    class Notifications:
        async def process(self, *_args, **_kwargs):
            return ()

    counts = {"broker_calls": 4, "broker_attempts": 2}
    run_id = _new_deferred_stage_run(db_session, counts=counts)
    extraction = Extraction()
    scoring = Scoring()
    deep = Deep()
    pipeline = _stage_pipeline_with_hooks(
        db_session,
        extraction=extraction,
        scoring=scoring,
        deep=deep,
        notifications=Notifications(),
    )

    asyncio.run(pipeline.run(run_id))
    _assert_stage_deferred(
        db_session, run_id, stage="deep_evaluation", cursor=0, counts=counts
    )
    asyncio.run(pipeline.run(run_id))

    from role_radar.db.models import JobSearchRun

    db_session.expire_all()
    run = db_session.get(JobSearchRun, run_id)
    assert run.status is JobSearchRunStatus.DEFERRED
    assert run.canary_checkpoint_json["stage"] == "deep_evaluation"
    assert run.canary_checkpoint_json["cursor"] == 0
    assert run.canary_checkpoint_json["counts"] == counts
    assert extraction.execute_calls == 1
    assert scoring.calls == 1
    assert deep.prepare_calls == 1
    assert deep.process_calls == 2
    assert pipeline._discovery.prepare_calls == 1
    assert pipeline._collection.calls == 0

def test_pipeline_defers_at_notifications_then_retries_without_deep_evaluation(db_session) -> None:
    from role_radar.domain.enums import ExtractionStatus, JobSearchRunStatus
    from role_radar.execution_budget import reserve_network_attempt

    class Extraction:
        execute_calls = 0

        def prepare(self, job_id):
            return job_id

        async def execute(self, _prepared):
            self.execute_calls += 1
            return object()

        def finalize(self, _execution):
            return type(
                "Finalized",
                (),
                {"status": ExtractionStatus.VALID, "retry_corrective": False},
            )()

    class Scoring:
        calls = 0

        def score(self, _run_id, _job_ids):
            self.calls += 1

    class Deep:
        process_calls = 0

        async def process(self, _run_id):
            self.process_calls += 1

        def prepare_queue(self, _run_id, _job_ids):
            pass

    class Notifications:
        calls = 0

        async def process(self, *_args, **_kwargs):
            self.calls += 1
            reserve_network_attempt("notification_batches")
            raise AssertionError("the exhausted notification ceiling must block before I/O")

    counts = {
        "broker_calls": 1,
        "broker_attempts": 2,
        "notification_batches": 1,
    }
    run_id = _new_deferred_stage_run(
        db_session, notification_mode="match_alerts", counts=counts
    )
    extraction = Extraction()
    scoring = Scoring()
    deep = Deep()
    notifications = Notifications()
    pipeline = _stage_pipeline_with_hooks(
        db_session,
        extraction=extraction,
        scoring=scoring,
        deep=deep,
        notifications=notifications,
    )

    asyncio.run(pipeline.run(run_id))
    _assert_stage_deferred(
        db_session, run_id, stage="notifications", cursor=0, counts=counts
    )
    asyncio.run(pipeline.run(run_id))

    from role_radar.db.models import JobSearchRun

    db_session.expire_all()
    run = db_session.get(JobSearchRun, run_id)
    assert run.status is JobSearchRunStatus.DEFERRED
    assert run.canary_checkpoint_json["stage"] == "notifications"
    assert run.canary_checkpoint_json["cursor"] == 0
    assert run.canary_checkpoint_json["counts"] == counts
    assert extraction.execute_calls == 1
    assert scoring.calls == 1
    assert deep.process_calls == 1
    assert notifications.calls == 2
    assert pipeline._discovery.prepare_calls == 1
    assert pipeline._collection.calls == 0
