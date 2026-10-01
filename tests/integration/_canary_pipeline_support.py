from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository
from role_radar.worker.pipeline import Pipeline


def _resumable_pipeline(session, *, extraction=None, deep=None, notifications=None, stage: str):
    class Eligibility:
        async def process(self, _run_id):
            return {"complete": True}

    class ForbiddenProducer:
        def prepare(self, _run_id):
            raise AssertionError("a deferred canary must not rerun discovery")

    class ForbiddenCollection:
        def prepare(self, *_args, **_kwargs):
            raise AssertionError("a deferred canary must not rerun ATS collection")

        def start_run_budget(self):
            raise AssertionError("a deferred canary must not reset collection budget")

    class Scoring:
        calls = 0

        def score(self, _run_id, _job_ids):
            self.calls += 1

    pipeline = Pipeline.__new__(Pipeline)
    pipeline._session_factory = lambda: session
    pipeline._eligibility = Eligibility()
    pipeline._discovery = ForbiddenProducer()
    pipeline._collection = ForbiddenCollection()
    pipeline._scoring = Scoring()
    pipeline._deep = deep
    pipeline._notifications = notifications
    pipeline._notification_recipient = "disabled"
    pipeline._settings = None
    return pipeline


def _new_deferred_stage_run(
    db_session,
    *,
    notification_mode="none",
    prior_completed=False,
    counts=None,
):
    from datetime import UTC, datetime

    from role_radar.db.models import Job, RunJob
    from role_radar.domain.enums import RunJobStage, RunJobStatus

    run = RunRepository(db_session).create_run("canary", notification_mode=notification_mode)
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.canary_checkpoint_json = {
        "version": 1,
        "stage": "discovery",
        "cursor": 0,
        "counts": counts or {"broker_calls": 1, "broker_attempts": 2},
        "reservations": [],
        "logical_reservations": [],
    }
    db_session.add(Job(id="stage-job", title="Engineer", company="Acme"))
    db_session.add(
        RunJob(
            run_id=run.id,
            job_id="stage-job",
            stage=RunJobStage.DEDUPLICATED,
            status=RunJobStatus.SUCCEEDED,
        )
    )
    if prior_completed:
        db_session.add(Job(id="a-job", title="Engineer", company="Acme"))
        db_session.add_all(
            [
                RunJob(
                    run_id=run.id,
                    job_id="a-job",
                    stage=RunJobStage.DEDUPLICATED,
                    status=RunJobStatus.SUCCEEDED,
                    created_at=datetime(2020, 1, 1, tzinfo=UTC),
                ),
                RunJob(
                    run_id=run.id,
                    job_id="a-job",
                    stage=RunJobStage.EXTRACTED,
                    status=RunJobStatus.SUCCEEDED,
                    created_at=datetime(2020, 1, 1, tzinfo=UTC),
                ),
            ]
        )
    db_session.commit()
    return run.id

def _stage_pipeline_with_hooks(
    db_session, *, extraction, scoring, deep, notifications
):
    from types import SimpleNamespace

    pipeline = _resumable_pipeline(
        db_session,
        extraction=extraction,
        deep=deep,
        notifications=notifications,
        stage="discovery",
    )
    pipeline._extraction = extraction
    pipeline._scoring = scoring

    class Discovery:
        prepare_calls = 0

        def prepare(self, _run_id):
            self.prepare_calls += 1
            return object()

        async def execute(self, _plan):
            return object()

        def finalize(self, _execution):
            return SimpleNamespace(
                status="ok", cycle_id="no-discovery-cycle", producer_success=True
            )

    class Collection:
        calls = 0

        def prepare(self, *_args, **_kwargs):
            self.calls += 1
            return ()

        def start_run_budget(self):
            self.calls += 1

        async def execute(self, _snapshot):
            self.calls += 1

    pipeline._discovery = Discovery()
    pipeline._collection = Collection()
    return pipeline

def _assert_stage_deferred(db_session, run_id, *, stage, counts, cursor=0):
    from role_radar.db.models import JobSearchRun
    from role_radar.domain.enums import JobSearchRunStatus

    db_session.expire_all()
    run = db_session.get(JobSearchRun, run_id)
    assert run.status is JobSearchRunStatus.DEFERRED
    assert run.canary_checkpoint_json["stage"] == stage
    assert run.canary_checkpoint_json["cursor"] == cursor
    assert run.canary_checkpoint_json["counts"] == counts
    assert run.canary_checkpoint_json["reservations"] == []
    assert run.canary_checkpoint_json["logical_reservations"] == []
