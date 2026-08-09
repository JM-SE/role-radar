"""Static source metadata catalog; no SQL, HTTP, or mutation policy."""

from role_radar.domain.enums import SourceType
from role_radar.sources.contracts import AuthMode, PagingMode, ResourceBounds, SourceCatalogEntry

_ORIGIN = "https://boards-api.greenhouse.io"
_LEVER_GLOBAL_ORIGIN = "https://api.lever.co"
_LEVER_EU_ORIGIN = "https://api.eu.lever.co"
_JOBICY_ORIGIN = "https://jobicy.com"

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
    SourceType.LEVER: SourceCatalogEntry(
        source_type=SourceType.LEVER,
        display_name="Lever Postings",
        docs_url="https://hire.lever.co/developer/documentation",
        # Mailbox is a worker capability, not a JobCollector factory.  Keeping
        # this false preserves the collector registry boundary; SourceService
        # has the separate EMAIL configuration path.
        adapter_available=True,
        configuration_model="LeverSourceConfigV1",
        configuration_version=1,
        factory_ref="lever.v1",
        canonicalizer_ref="lever_source_key",
        auth_mode=AuthMode.NONE,
        allowed_origins=(_LEVER_GLOBAL_ORIGIN, _LEVER_EU_ORIGIN),
        paging=PagingMode.OFFSET,
        notes="Public Lever postings API; fixed regional origin and bounded offset collection.",
        resource_bounds=ResourceBounds(
            max_pages=6,
            max_items=500,
            max_bytes=8 * 1024 * 1024,
            max_duration_seconds=120.0,
            enforced=True,
        ),
    ),
    SourceType.JOBICY: SourceCatalogEntry(
        source_type=SourceType.JOBICY,
        display_name="Jobicy LATAM Remote Jobs",
        docs_url="https://jobicy.com/jobs-rss-feed",
        adapter_available=True,
        configuration_model="JobicySourceConfigV1",
        configuration_version=1,
        factory_ref="jobicy.v1",
        canonicalizer_ref="jobicy_source_key",
        auth_mode=AuthMode.NONE,
        allowed_origins=(_JOBICY_ORIGIN,),
        paging=PagingMode.NONE,
        notes=(
            "Fixed Jobicy LATAM JSON source; count=100, at most one request per hour. "
            "Preserve original Jobicy URLs and do not redistribute to external job boards."
        ),
        resource_bounds=ResourceBounds(
            max_pages=1,
            max_items=100,
            max_bytes=8 * 1024 * 1024,
            max_duration_seconds=120.0,
            enforced=True,
        ),
        terms_policy_version="jobicy-terms-v1",
    ),
    SourceType.EMAIL: SourceCatalogEntry(
        source_type=SourceType.EMAIL,
        display_name="RoleRadar Mailbox",
        docs_url="https://support.google.com/mail/answer/7126229",
        adapter_available=True,
        configuration_model="EmailSourceConfigV1",
        configuration_version=1,
        factory_ref=None,
        canonicalizer_ref="email_source_key",
        auth_mode=AuthMode.FUTURE,
        allowed_origins=("imap.gmail.com:993",),
        paging=PagingMode.NONE,
        notes="Worker-only Gmail IMAP read-only intake on the exact RoleRadar label.",
        resource_bounds=ResourceBounds(
            max_items=100,
            max_bytes=2 * 1024 * 1024,
            max_duration_seconds=30.0,
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
            notes="Visible catalog entry; adapter is not implemented.",
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
        or entry.canonicalizer_ref is None
        or (entry.factory_ref is None and entry.source_type is not SourceType.EMAIL)
        for entry in available
    ):
        raise AssertionError("available catalog entry is incomplete")
    if any(
        entry.factory_ref is not None for entry in CATALOG.values() if not entry.adapter_available
    ):
        raise AssertionError("unavailable catalog entry has a factory")


validate_catalog_consistency()
