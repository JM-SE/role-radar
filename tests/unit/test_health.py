"""Tests del endpoint GET /health."""

import httpx


async def test_health_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"status": "ok", "version": "0.1.0", "environment": "dev"}
