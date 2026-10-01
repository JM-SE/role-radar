import asyncio

import pytest
from sqlalchemy.orm import Session

from role_radar.domain.enums import JobSearchRunStatus
from role_radar.execution_budget import CANARY_BUDGET
from role_radar.repositories.runs import RunRepository


@pytest.mark.parametrize(
    "checkpoint",
    [
        None,
        [],
        {"version": 2, "stage": "discovery", "cursor": 0},
        {"version": True, "stage": "discovery", "cursor": 0},
        {"version": 1.0, "stage": "discovery", "cursor": 0},
        {"version": 1, "stage": "unsupported", "cursor": 0},
        {"version": 1, "stage": "discovery", "cursor": True},
        {"version": 1, "stage": "discovery", "cursor": -1},
        {"version": 1, "stage": "discovery", "cursor": "0"},
        {"version": 1, "stage": "discovery", "cursor": 0, "counts": []},
        {"version": 1, "stage": "discovery", "cursor": 0, "counts": {"broker_calls": True}},
        {"version": 1, "stage": "discovery", "cursor": 0, "reservations": {}},
        {"version": 1, "stage": "discovery", "cursor": 0, "reservations": ["invalid"]},
        *[
            {"version": 1, "stage": "discovery", "cursor": 0, field: [record]}
            for field in ("reservations", "logical_reservations")
            for record in (
                {},
                {"kind": "broker_calls"},
                {"token": "00000000-0000-4000-8000-000000000001"},
                {
                    "token": "00000000-0000-4000-8000-000000000001",
                    "kind": "broker_calls",
                    "extra": "forbidden",
                },
                {"token": 123, "kind": "broker_calls"},
                {"token": "00000000-0000-4000-8000-000000000001", "kind": 123},
                {"token": "not-a-uuid", "kind": "broker_calls"},
                {"token": "00000000-0000-4000-8000-000000000001", "kind": "unknown"},
            )
        ],
    ],
)
def test_pipeline_rejects_malformed_checkpoint_before_producers_and_preserves_it(
    db_session, db_engine, checkpoint
) -> None:
    from role_radar.worker.pipeline import Pipeline

    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.canary_checkpoint_json = checkpoint
    db_session.commit()
    run_id = run.id

    class UnexpectedProducer:
        async def process(self, _run_id):
            raise AssertionError("malformed checkpoint must fail before producers")

    pipeline = Pipeline.__new__(Pipeline)
    pipeline._session_factory = lambda: Session(db_engine)
    pipeline._eligibility = UnexpectedProducer()
    asyncio.run(pipeline.run(run_id))

    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.error_code == "canary_checkpoint_invalid"
    assert persisted.canary_checkpoint_json == checkpoint
    assert persisted.status is JobSearchRunStatus.DEFERRED


def test_pipeline_rejects_valid_unresolved_reservation_as_ambiguous_before_producers(
    db_session, db_engine
) -> None:
    from role_radar.worker.pipeline import Pipeline

    checkpoint = {
        "version": 1,
        "stage": "discovery",
        "cursor": 0,
        "reservations": [
            {"token": "00000000-0000-4000-8000-000000000001", "kind": "broker_calls"}
        ],
    }
    run = RunRepository(db_session).create_run("canary")
    run.canary_budget_json = dict(CANARY_BUDGET)
    run.canary_checkpoint_json = checkpoint
    db_session.commit()
    run_id = run.id

    class UnexpectedProducer:
        async def process(self, _run_id):
            raise AssertionError("unresolved reservation must fail before producers")

    pipeline = Pipeline.__new__(Pipeline)
    pipeline._session_factory = lambda: Session(db_engine)
    pipeline._eligibility = UnexpectedProducer()
    asyncio.run(pipeline.run(run_id))

    db_session.expire_all()
    persisted = db_session.get(type(run), run_id)
    assert persisted.error_code == "canary_side_effect_unresolved"
    assert persisted.canary_checkpoint_json == checkpoint
    assert persisted.status is JobSearchRunStatus.DEFERRED
