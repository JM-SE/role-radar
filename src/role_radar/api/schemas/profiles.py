"""Schemas de perfiles candidato (POST /profiles, GET /profiles)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from role_radar.domain.profile import CandidateProfileV1


class ProfileCreate(BaseModel):
    """Strict v1 payload; version and schema are server-owned."""

    name: str
    profile_json: CandidateProfileV1
    model_config = ConfigDict(strict=True, extra="forbid")


class ProfileUpdate(BaseModel):
    profile_json: CandidateProfileV1
    model_config = ConfigDict(strict=True, extra="forbid")


class ProfileResponse(BaseModel):
    """Respuesta canónica de un perfil."""

    id: str
    name: str
    version: int
    schema_version: int
    profile_json: dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
