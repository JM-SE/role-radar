"""Control-plane tests: POST is intent-only and idempotent."""

import json

import httpx
from sqlalchemy.orm import Session

import role_radar.cli.main as cli_main
from role_radar.db.models import JobSearchRun

PROFILE = {
    "title": "backend engineer",
    "years_of_experience": 8,
    "target_roles": ["backend"],
    "target_titles": ["backend engineer"],
    "core_skills": ["python"],
    "secondary_skills": [],
    "regions": ["spain"],
    "remote_only": True,
    "employment_preferences": ["full_time"],
    "languages": {"english": "professional"},
    "excluded_roles": [],
    "excluded_technologies": [],
    "hard_constraints": {},
    "soft_preferences": {},
}


async def test_create_run_is_202_pending_and_reuses_key(client: httpx.AsyncClient) -> None:
    profile = await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})
    profile_id = profile.json()["id"]
    first = await client.post(
        "/runs",
        headers={"Idempotency-Key": "slot-1"},
        json={"reason": " scheduled ", "profile_id": profile_id},
    )
    assert first.status_code == 202
    assert first.json()["status"] == "pending"
    second = await client.post(
        "/runs",
        headers={"Idempotency-Key": "slot-1"},
        json={"reason": "scheduled", "profile_id": profile_id},
    )
    assert second.status_code == 202
    assert second.json()["id"] == first.json()["id"]


async def test_same_key_different_intent_is_409(client: httpx.AsyncClient) -> None:
    profile = await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})
    profile_id = profile.json()["id"]
    await client.post(
        "/runs",
        headers={"Idempotency-Key": "slot-1"},
        json={"reason": "one", "profile_id": profile_id},
    )
    conflict = await client.post(
        "/runs",
        headers={"Idempotency-Key": "slot-1"},
        json={"reason": "two", "profile_id": profile_id},
    )
    assert conflict.status_code == 409


async def test_get_run_allows_nested_operational_stats(
    client: httpx.AsyncClient, db_session
) -> None:
    profile = await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})
    created = await client.post(
        "/runs", json={"reason": "scheduled", "profile_id": profile.json()["id"]}
    )
    run = db_session.get(JobSearchRun, created.json()["id"])
    assert run is not None
    run.stats_json = {
        "collected": 12,
        "product_eligibility_reprocessing": {"policy_version": "v1", "attempted": 4},
    }
    db_session.commit()

    response = await client.get(f"/runs/{run.id}")

    assert response.status_code == 200
    assert response.json()["stats"] == run.stats_json


async def test_cli_default_notification_modes_are_public(
    client: httpx.AsyncClient, db_session, monkeypatch, capsys
) -> None:
    profile = await client.post("/profiles", json={"name": "CLI", "profile_json": PROFILE})
    profile_id = profile.json()["id"]
    engine = db_session.get_bind()

    class NoDispose:
        def dispose(self) -> None:
            pass

    monkeypatch.setattr(
        cli_main,
        "_open_session",
        lambda _settings: (NoDispose(), Session(engine)),
    )

    cases = (
        (["run", "create", "--canary", "--profile-id", profile_id], "match_alerts"),
        (["run", "create", "--profile-id", profile_id], "none"),
        (
            ["run", "create", "--reason", "scheduled", "--profile-id", profile_id],
            "match_alerts",
        ),
    )
    for args, expected_mode in cases:
        assert cli_main.main(args) == 0
        output = capsys.readouterr()
        assert output.err == ""
        created = json.loads(output.out)
        assert set(created) == {"id", "status"}
        response = await client.get(f"/runs/{created['id']}")
        assert response.status_code == 200
        assert response.json()["notification_mode"] == expected_mode
