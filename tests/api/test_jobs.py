"""Tests de API de ofertas, incluido el criterio de salida de Fase 1
(spec phase-01 §10.3): seed → GET /jobs/{id} → 200 con campos del seed."""

from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from role_radar.db.seed import load_fixtures
from role_radar.services.matching_service import MatchingService

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture
def seeded(db_session: Session) -> dict[str, str]:
    """Carga los fixtures de seed en la DB de test."""
    return load_fixtures(db_session, FIXTURES_DIR)


async def test_get_job_from_seed_returns_expected_fields(
    client: httpx.AsyncClient, seeded: dict[str, str]
) -> None:
    """Criterio de salida F1: seed → GET /jobs/{id} 200 con title/company/status."""
    response = await client.get(f"/jobs/{seeded['job_id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == seeded["job_id"]
    assert body["title"] == "Backend Engineer"
    assert body["company"] == "Acme"
    assert body["status"] == "new"
    assert body["application_url"] == "https://boards.greenhouse.io/acme/jobs/123"


async def test_get_job_detail_includes_source_references(
    client: httpx.AsyncClient, seeded: dict[str, str]
) -> None:
    response = await client.get(f"/jobs/{seeded['job_id']}")
    assert response.status_code == 200
    body = response.json()
    assert len(body["source_references"]) == 1
    ref = body["source_references"][0]
    assert ref["source_id"] == seeded["source_id"]
    assert ref["external_id"] == "123"
    assert ref["source_url"] == "https://boards.greenhouse.io/acme/jobs/123"
    assert ref["collected_at"]


async def test_list_jobs_with_filters(client: httpx.AsyncClient, seeded: dict[str, str]) -> None:
    response = await client.get("/jobs")
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = await client.get("/jobs", params={"status": "active"})
    assert response.json() == []

    response = await client.get("/jobs", params={"company": "Acme"})
    assert len(response.json()) == 1

    response = await client.get("/jobs", params={"limit": 1, "offset": 0})
    assert len(response.json()) == 1


async def test_get_job_not_found(client: httpx.AsyncClient) -> None:
    response = await client.get("/jobs/no-existe")
    assert response.status_code == 404


async def test_ranking_includes_explainable_latest_score(
    client: httpx.AsyncClient, seeded: dict[str, str], db_session: Session
) -> None:
    score = MatchingService(db_session).score_job(
        job_id=seeded["job_id"], profile_id=seeded["profile_id"]
    )
    db_session.commit()
    response = await client.get(
        "/jobs",
        params={"profile_id": seeded["profile_id"], "minimum_score": score.preliminary_score},
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["latest_score"]["id"] == score.id
    assert body[0]["latest_score"]["signals"]


async def test_no_post_jobs_endpoint(client: httpx.AsyncClient) -> None:
    """D15: sin POST /jobs en F1 (escritura de ofertas = worker, fases 5+)."""
    response = await client.post("/jobs", json={"title": "X", "company": "Y"})
    assert response.status_code == 405
