"""Collector asíncrono para la API pública de Greenhouse Boards."""

from datetime import UTC, datetime
from typing import Any

import httpx

from role_radar.collectors.protocols import CollectionContext
from role_radar.domain.dto import RawJob

GREENHOUSE_BOARDS_API_BASE = "https://boards-api.greenhouse.io/v1/boards"


class GreenhouseCollector:
    """Solo HTTP y mapeo de payload Greenhouse a ``RawJob``."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        user_agent: str = "role-radar/0.1 (+homelab)",
    ) -> None:
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._user_agent = user_agent

    async def __aenter__(self) -> "GreenhouseCollector":
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def collect(self, context: CollectionContext) -> list[RawJob]:
        headers = {"User-Agent": self._user_agent, "Accept": "application/json"}
        list_url = f"{GREENHOUSE_BOARDS_API_BASE}/{context.board_token}/jobs"
        response = await self._client.get(list_url, headers=headers, timeout=self._timeout)
        response.raise_for_status()
        payload = response.json()
        jobs = payload.get("jobs", []) if isinstance(payload, dict) else payload
        if not isinstance(jobs, list):
            return []

        collected: list[RawJob] = []
        for item in jobs:
            if not isinstance(item, dict) or "id" not in item:
                continue
            job_payload = dict(item)
            if not job_payload.get("content"):
                detail_url = f"{list_url}/{job_payload['id']}"
                detail_response = await self._client.get(
                    detail_url,
                    params={"content": "true"},
                    headers=headers,
                    timeout=self._timeout,
                )
                detail_response.raise_for_status()
                detail = detail_response.json()
                if isinstance(detail, dict):
                    job_payload.update(detail.get("job", detail))

            absolute_url = job_payload.get("absolute_url")
            location = job_payload.get("location")
            if isinstance(location, dict):
                location = location.get("name")
            elif location is not None and not isinstance(location, str):
                location = str(location)

            structured_data = {
                key: job_payload[key]
                for key in ("id", "title", "location", "absolute_url", "updated_at", "metadata")
                if key in job_payload
            }
            collected.append(
                RawJob(
                    source="greenhouse",
                    external_id=str(job_payload["id"]),
                    source_url=absolute_url,
                    application_url=job_payload.get("application_url", absolute_url),
                    title=str(job_payload.get("title", "")),
                    company=context.company or context.source_name,
                    location=location,
                    description=job_payload.get("content"),
                    structured_data=structured_data,
                    collected_at=datetime.now(UTC),
                )
            )
        return collected
