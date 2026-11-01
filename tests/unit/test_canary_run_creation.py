import json
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from role_radar.cli.main import main
from role_radar.db.base import Base
from role_radar.db.models import CandidateProfile, JobSearchRun
from role_radar.domain.enums import JobSearchRunStatus
from role_radar.execution_budget import CANARY_BUDGET, validate_canary_checkpoint


def test_cli_persists_fresh_canary_budget_and_valid_discovery_checkpoint(
    tmp_path, monkeypatch, capsys
) -> None:
    database = tmp_path / "canary.db"
    engine = create_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)
    profile_id = str(uuid4())
    with Session(engine) as session:
        session.add(
            CandidateProfile(
                id=profile_id,
                name="offline-test",
                version=1,
                schema_version=1,
                profile_json={},
                is_active=True,
            )
        )
        session.commit()

    monkeypatch.setenv("ROLE_RADAR_DATABASE_URL", f"sqlite:///{database}")
    create_rc = main(["run", "create", "--canary", "--profile-id", profile_id])
    create_output = capsys.readouterr()
    assert create_rc == 0, create_output
    created = json.loads(create_output.out)
    assert set(created) == {"id", "status"}
    assert created["status"] == "pending"
    run_id = created["id"]

    with Session(engine) as session:
        run = session.get(JobSearchRun, run_id)
        assert run is not None
        assert run.canary_budget_json == CANARY_BUDGET
        assert validate_canary_checkpoint(run.canary_checkpoint_json) == ("discovery", 0)
        assert run.canary_checkpoint_json == {
            "version": 1,
            "stage": "discovery",
            "cursor": 0,
            "counts": {},
            "reservations": [],
            "logical_reservations": [],
        }

    assert main(["run", "show", "--run-id", run_id]) == 0
    assert json.loads(capsys.readouterr().out) == {"id": run_id, "status": "pending"}

    assert main(["run", "create", "--profile-id", profile_id]) == 0
    ordinary = json.loads(capsys.readouterr().out)
    assert set(ordinary) == {"id", "status"}
    ordinary_id = ordinary["id"]
    with Session(engine) as session:
        ordinary = session.get(JobSearchRun, ordinary_id)
        assert ordinary is not None
        assert ordinary.canary_budget_json is None
        assert ordinary.canary_checkpoint_json is None

    assert main(["run", "create", "--reason", "scheduled", "--profile-id", profile_id]) == 0
    scheduled = json.loads(capsys.readouterr().out)
    assert set(scheduled) == {"id", "status"}
    scheduled_id = scheduled["id"]
    with Session(engine) as session:
        scheduled_run = session.get(JobSearchRun, scheduled_id)
        assert scheduled_run is not None
        scheduled_run.status = JobSearchRunStatus.COMPLETED
        session.commit()
    assert main(["run", "retry", "--run-id", scheduled_id]) == 0
    retried = json.loads(capsys.readouterr().out)
    assert set(retried) == {"id", "status"}
    assert retried["status"] == "pending"

    assert (
        main(
            [
                "run",
                "create",
                "--canary",
                "--no-notifications",
                "--profile-id",
                profile_id,
            ]
        )
        == 0
    )
    opted_out = json.loads(capsys.readouterr().out)
    assert set(opted_out) == {"id", "status", "notification_mode"}
    assert opted_out["status"] == "pending"
    assert opted_out["notification_mode"] == "none"

    assert main(["run", "list"]) == 0
    before_rejection = capsys.readouterr()
    assert before_rejection.err == ""
    assert main(["run", "create", "--no-notifications", "--profile-id", profile_id]) == 1
    rejected = capsys.readouterr()
    assert rejected.out == ""
    assert rejected.err == "role-radar: no_notifications_requires_canary\n"
    assert main(["run", "list"]) == 0
    after_rejection = capsys.readouterr()
    assert after_rejection.out == before_rejection.out
    assert after_rejection.err == ""
    engine.dispose()
