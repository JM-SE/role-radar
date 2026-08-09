"""Descubrimiento opcional y curado de boards."""

from role_radar.discovery.fake_provider import FakeSearchProvider
from role_radar.discovery.null_provider import NullSearchProvider
from role_radar.discovery.planner import QueryPlannerV1
from role_radar.discovery.protocols import SearchProvider, SearchQuery, SearchResult
from role_radar.discovery.query_keys import QueryKeyFactory
from role_radar.discovery.url_classifier import classify, classify_url

__all__ = [
    "FakeSearchProvider",
    "NullSearchProvider",
    "QueryKeyFactory",
    "QueryPlannerV1",
    "SearchProvider",
    "SearchQuery",
    "SearchResult",
    "classify",
    "classify_url",
]
