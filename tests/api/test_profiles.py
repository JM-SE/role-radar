"""Tests de API de perfiles versionados (D28)."""

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


async def test_create_profile_returns_201(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/profiles",
        json={"name": "Perfil A", "profile_json": PROFILE},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Perfil A"
    assert body["version"] == 1
    assert body["is_active"] is True
    assert body["profile_json"]["target_roles"] == ["backend"]
    assert body["id"]
    assert body["created_at"]


async def test_create_profile_with_custom_version(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/profiles",
        json={"name": "Perfil B", "profile_json": PROFILE},
    )
    assert response.status_code == 201
    assert response.json()["version"] == 1


async def test_list_profiles(client: httpx.AsyncClient) -> None:
    await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})
    other = {**PROFILE, "target_roles": ["platform"]}
    await client.post("/profiles", json={"name": "B", "profile_json": other})

    response = await client.get("/profiles")
    assert response.status_code == 200
    names = {p["name"] for p in response.json()}
    assert names == {"A", "B"}


async def test_get_profile_by_id(client: httpx.AsyncClient) -> None:
    created = (await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})).json()

    response = await client.get(f"/profiles/{created['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == created["id"]


async def test_get_profile_not_found(client: httpx.AsyncClient) -> None:
    response = await client.get("/profiles/no-existe")
    assert response.status_code == 404


async def test_legacy_profile_is_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/profiles", json={"name": "Legacy", "profile_json": {"roles_target": ["backend"]}}
    )
    assert response.status_code == 422


async def test_put_creates_new_active_version(client: httpx.AsyncClient) -> None:
    created = (await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})).json()
    updated = {**PROFILE, "target_roles": ["platform"]}
    response = await client.put(f"/profiles/{created['id']}", json={"profile_json": updated})
    assert response.status_code == 200
    assert response.json()["id"] != created["id"]
    assert response.json()["version"] == 2
    assert response.json()["is_active"] is True
    predecessor = await client.get(f"/profiles/{created['id']}")
    assert predecessor.json()["is_active"] is False


async def test_repeating_put_on_inactive_predecessor_is_conflict_without_v3(
    client: httpx.AsyncClient,
) -> None:
    created = (await client.post("/profiles", json={"name": "A", "profile_json": PROFILE})).json()
    updated = {**PROFILE, "target_roles": ["platform"]}
    first = await client.put(f"/profiles/{created['id']}", json={"profile_json": updated})
    assert first.status_code == 200

    repeated = await client.put(f"/profiles/{created['id']}", json={"profile_json": PROFILE})
    assert repeated.status_code == 409

    history = await client.get("/profiles")
    assert len(history.json()) == 1
    all_versions = [
        (await client.get(f"/profiles/{profile_id}"))
        for profile_id in (created["id"], first.json()["id"])
    ]
    assert {response.json()["version"] for response in all_versions} == {1, 2}


async def test_profile_identity_contract(client: httpx.AsyncClient) -> None:
    health = await client.get("/health")
    assert health.status_code == 200
    assert set(health.json()) == {"status", "version", "environment"}
    assert health.json()["status"] == "ok"

    openapi = await client.get("/openapi.json")
    assert openapi.status_code == 200
    assert {"/profiles", "/jobs", "/runs", "/sources"} <= set(openapi.json()["paths"])
