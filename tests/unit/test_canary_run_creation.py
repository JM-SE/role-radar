import json
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from role_radar.cli.main import main
from role_radar.db.base import Base
from role_radar.db.models import CandidateProfile, JobSearchRun
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
    assert main(["run", "create", "--canary", "--profile-id", profile_id]) == 0
    run_id = json.loads(capsys.readouterr().out)["id"]

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

    assert main(["run", "create", "--profile-id", profile_id]) == 0
    ordinary_id = json.loads(capsys.readouterr().out)["id"]
    with Session(engine) as session:
        ordinary = session.get(JobSearchRun, ordinary_id)
        assert ordinary is not None
        assert ordinary.canary_budget_json is None
        assert ordinary.canary_checkpoint_json is None
    engine.dispose()
