"""Sanitized read-only source API DTOs."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from role_radar.domain.enums import SourceType
from role_radar.sources.contracts import AuthMode, PagingMode


class SourceTypeResponse(BaseModel):
    source_type: SourceType
    display_name: str
    docs_url: str
    adapter_available: bool
    configuration_version: int | None
    auth_mode: AuthMode
    allowed_origins: tuple[str, ...]
    paging: PagingMode
    notes: str
    resource_bounds_enforced: bool = False


class SourceResponse(BaseModel):
    id: str
    source_type: SourceType
    source_key: str
    name: str
    configuration_version: int
    public_configuration: dict[str, str]
    adapter_available: bool
    reconciliation_required: bool
    enabled: bool
    revision: int
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    last_error_code: str | None

    model_config = ConfigDict(extra="forbid")


class SourcePage(BaseModel):
    items: list[SourceResponse]
    total: int
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
