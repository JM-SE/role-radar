"""Descubrimiento opcional y curado de boards."""

from role_radar.discovery.fake_provider import FakeSearchProvider
from role_radar.discovery.null_provider import NullSearchProvider
from role_radar.discovery.protocols import SearchProvider, SearchQuery, SearchResult

__all__ = [
    "FakeSearchProvider",
    "NullSearchProvider",
    "SearchProvider",
    "SearchQuery",
    "SearchResult",
]
