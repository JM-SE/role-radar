"""Read-only source catalog and source projections."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from role_radar.api.deps import get_source_service
from role_radar.api.schemas.sources import SourcePage, SourceResponse, SourceTypeResponse
from role_radar.db.models import Source
from role_radar.domain.enums import SourceType
from role_radar.services.source_service import SourceNotFound, SourceService, SourceServiceError
from role_radar.sources.catalog import list_catalog
from role_radar.sources.public import project_public_configuration

router = APIRouter(tags=["sources"])


@router.get("/source-types", response_model=list[SourceTypeResponse])
def source_types() -> list[SourceTypeResponse]:
    return [
        SourceTypeResponse(
            source_type=entry.source_type,
            display_name=entry.display_name,
            docs_url=entry.docs_url,
            adapter_available=entry.adapter_available,
            configuration_version=entry.configuration_version,
            auth_mode=entry.auth_mode,
            allowed_origins=entry.allowed_origins,
            paging=entry.paging,
            notes=entry.notes,
            resource_bounds_enforced=entry.resource_bounds.enforced,
        )
        for entry in list_catalog()
    ]


@router.get("/sources", response_model=SourcePage)
def list_sources(
    service: Annotated[SourceService, Depends(get_source_service)],
    source_type: SourceType | None = None,
    enabled: bool | None = None,
    archived: bool | None = None,
    adapter_available: bool | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> SourcePage:
    rows, total = service.list_sources(
        source_type=source_type,
        enabled=enabled,
        archived=archived,
        adapter_available=adapter_available,
        limit=limit,
        offset=offset,
    )
    return SourcePage(
        items=[_project(row) for row in rows], total=total, limit=limit, offset=offset
    )


@router.get("/sources/{source_id}", response_model=SourceResponse)
def get_source(
    source_id: str,
    service: Annotated[SourceService, Depends(get_source_service)],
) -> SourceResponse:
    try:
        return _project(service.get(source_id))
    except SourceNotFound as exc:
        raise HTTPException(status_code=404, detail=exc.code) from exc
    except SourceServiceError as exc:
        raise HTTPException(status_code=409, detail=exc.code) from exc


def _project(row: Source) -> SourceResponse:
    # Keep ORM access in this mapping function and only pass an allowlisted
    # projection to Pydantic; raw JSON never becomes an API DTO.
    source_type = row.type
    version = row.configuration_version
    public = project_public_configuration(source_type, version, row.configuration)
    public_config = public.as_dict() if hasattr(public, "as_dict") else dict(public)
    available = next(
        entry.adapter_available for entry in list_catalog() if entry.source_type is source_type
    )
    return SourceResponse(
        id=row.id,
        source_type=source_type,
        source_key=row.source_key,
        name=row.name,
        configuration_version=version,
        public_configuration=public_config,
        adapter_available=available,
        reconciliation_required=not available or version == 0,
        enabled=row.enabled,
        revision=row.revision,
        created_at=row.created_at,
        updated_at=row.updated_at,
        archived_at=row.archived_at,
        last_success_at=row.last_success_at,
        last_error_at=row.last_error_at,
        last_error_code=row.last_error_code,
    )
