"""Static source metadata catalog; no SQL, HTTP, or mutation policy."""

from role_radar.domain.enums import SourceType
from role_radar.sources.contracts import AuthMode, PagingMode, ResourceBounds, SourceCatalogEntry

_ORIGIN = "https://boards-api.greenhouse.io"

_ENTRIES: dict[SourceType, SourceCatalogEntry] = {
    SourceType.GREENHOUSE: SourceCatalogEntry(
        source_type=SourceType.GREENHOUSE,
        display_name="Greenhouse Boards",
        docs_url="https://developers.greenhouse.io/job-board.html",
        adapter_available=True,
        configuration_model="GreenhouseSourceConfig",
        configuration_version=1,
        factory_ref="greenhouse.v1",
        canonicalizer_ref="greenhouse_source_key",
        auth_mode=AuthMode.NONE,
        allowed_origins=(_ORIGIN,),
        paging=PagingMode.NONE,
        notes="Public Greenhouse board API; fixed-origin bounded single-page collection.",
        resource_bounds=ResourceBounds(
            max_pages=1,
            max_items=500,
            max_bytes=8 * 1024 * 1024,
            max_duration_seconds=120.0,
            enforced=True,
        ),
    ),
}

for _source_type in SourceType:
    _ENTRIES.setdefault(
        _source_type,
        SourceCatalogEntry(
            source_type=_source_type,
            display_name=_source_type.value.replace("_", " ").title(),
            docs_url="https://role-radar.invalid/source-types",
            adapter_available=False,
            configuration_model=None,
            configuration_version=None,
            factory_ref=None,
            canonicalizer_ref=None,
            auth_mode=AuthMode.FUTURE,
            allowed_origins=(),
            paging=PagingMode.NONE,
            notes="Visible catalog entry; adapter is not implemented in F8.1.",
            resource_bounds=ResourceBounds(),
        ),
    )

CATALOG = dict(_ENTRIES)


def get_catalog_entry(source_type: SourceType | str) -> SourceCatalogEntry:
    return CATALOG[SourceType(source_type)]


def list_catalog() -> tuple[SourceCatalogEntry, ...]:
    return tuple(CATALOG[source_type] for source_type in SourceType)


def validate_catalog_consistency() -> None:
    available = [entry for entry in CATALOG.values() if entry.adapter_available]
    if any(
        entry.configuration_model is None
        or entry.configuration_version is None
        or entry.factory_ref is None
        or entry.canonicalizer_ref is None
        for entry in available
    ):
        raise AssertionError("available catalog entry is incomplete")
    if any(
        entry.factory_ref is not None for entry in CATALOG.values() if not entry.adapter_available
    ):
        raise AssertionError("unavailable catalog entry has a factory")


validate_catalog_consistency()
