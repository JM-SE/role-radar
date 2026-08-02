"""Control-plane tests: POST is intent-only and idempotent."""

import httpx

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
