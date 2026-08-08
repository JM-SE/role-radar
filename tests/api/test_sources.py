import httpx
from sqlalchemy.orm import Session

from role_radar.services.source_service import SourceService


async def test_sources_are_sanitized_and_read_only(
    client: httpx.AsyncClient, db_session: Session
) -> None:
    source = SourceService(db_session).create(
        source_type="greenhouse", name="Board", configuration={"board_token": "acme"}
    )
    response = await client.get("/sources")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["public_configuration"] == {"board_token": "acme"}
    assert "configuration" not in body["items"][0]
    assert (await client.get(f"/sources/{source.id}")).status_code == 200
    assert (await client.get("/sources/unknown")).json()["detail"] == "source_not_found"
    for method in ("post", "put", "patch", "delete"):
        assert (await getattr(client, method)("/sources")).status_code == 405
