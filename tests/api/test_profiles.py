"""Tests de API de perfiles (D15: POST + GET list + GET by id)."""

import httpx


async def test_create_profile_returns_201(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/profiles",
        json={"name": "Perfil A", "profile_json": {"roles": ["backend"]}},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Perfil A"
    assert body["version"] == 1
    assert body["is_active"] is True
    assert body["profile_json"] == {"roles": ["backend"]}
    assert body["id"]
    assert body["created_at"]


async def test_create_profile_with_custom_version(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/profiles",
        json={"name": "Perfil B", "profile_json": {}, "version": 2},
    )
    assert response.status_code == 201
    assert response.json()["version"] == 2


async def test_list_profiles(client: httpx.AsyncClient) -> None:
    await client.post("/profiles", json={"name": "A", "profile_json": {}})
    await client.post("/profiles", json={"name": "B", "profile_json": {}})

    response = await client.get("/profiles")
    assert response.status_code == 200
    names = {p["name"] for p in response.json()}
    assert names == {"A", "B"}


async def test_get_profile_by_id(client: httpx.AsyncClient) -> None:
    created = (await client.post("/profiles", json={"name": "A", "profile_json": {}})).json()

    response = await client.get(f"/profiles/{created['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == created["id"]


async def test_get_profile_not_found(client: httpx.AsyncClient) -> None:
    response = await client.get("/profiles/no-existe")
    assert response.status_code == 404
