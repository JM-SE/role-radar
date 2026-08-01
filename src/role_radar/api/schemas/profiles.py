"""Schemas de perfiles candidato (POST /profiles, GET /profiles)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ProfileCreate(BaseModel):
    """Payload de POST /profiles (D15: name, profile_json, version?)."""

    name: str
    profile_json: dict[str, Any]
    version: int = 1


class ProfileResponse(BaseModel):
    """Respuesta canónica de un perfil."""

    id: str
    name: str
    version: int
    profile_json: dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
