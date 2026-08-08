from role_radar.collectors.registry import REGISTRY
from role_radar.domain.enums import SourceType
from role_radar.sources.catalog import CATALOG, list_catalog


def test_all_source_types_are_visible_and_only_greenhouse_is_available() -> None:
    assert {entry.source_type for entry in list_catalog()} == set(SourceType)
    available = [entry for entry in CATALOG.values() if entry.adapter_available]
    assert [entry.source_type for entry in available] == [SourceType.GREENHOUSE]
    assert set(REGISTRY) == {"greenhouse.v1"}
