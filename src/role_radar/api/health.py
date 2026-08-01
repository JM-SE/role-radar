"""Endpoint de salud de la aplicación."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from role_radar.api.deps import get_settings
from role_radar.config import Settings

router = APIRouter()


class HealthResponse(BaseModel):
    """Contrato del endpoint GET /health."""

    status: Literal["ok"] = "ok"
    version: str
    environment: str


@router.get("/health", response_model=HealthResponse)
async def health(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> HealthResponse:
    """Devuelve el estado de la aplicación y su versión."""
    return HealthResponse(
        version=request.app.state.version,
        environment=settings.environment,
    )
