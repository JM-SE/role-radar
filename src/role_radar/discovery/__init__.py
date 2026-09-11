"""Descubrimiento opcional y curado de boards.

The package keeps its historical convenience exports, but resolves them only
when explicitly requested.  This prevents importing an offline artifact
parser from eagerly loading provider and collector implementations.
"""

from importlib import import_module

_LAZY_EXPORTS = {
    "FakeSearchProvider": ("role_radar.discovery.fake_provider", "FakeSearchProvider"),
    "NullSearchProvider": ("role_radar.discovery.null_provider", "NullSearchProvider"),
    "ProviderTier": ("role_radar.discovery.contracts", "ProviderTier"),
    "QueryKeyFactory": ("role_radar.discovery.query_keys", "QueryKeyFactory"),
    "QueryPlannerV1": ("role_radar.discovery.planner", "QueryPlannerV1"),
    "SearchProvider": ("role_radar.discovery.protocols", "SearchProvider"),
    "SearchQuery": ("role_radar.discovery.protocols", "SearchQuery"),
    "SearchRequest": ("role_radar.discovery.contracts", "SearchRequest"),
    "SearchResponse": ("role_radar.discovery.contracts", "SearchResponse"),
    "SearchResult": ("role_radar.discovery.protocols", "SearchResult"),
    "TransientSearchHit": ("role_radar.discovery.contracts", "TransientSearchHit"),
    "classify": ("role_radar.discovery.url_classifier", "classify"),
    "classify_url": ("role_radar.discovery.url_classifier", "classify_url"),
}


def __getattr__(name: str) -> object:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value

__all__ = [
    "FakeSearchProvider",
    "NullSearchProvider",
    "ProviderTier",
    "QueryKeyFactory",
    "QueryPlannerV1",
    "SearchProvider",
    "SearchQuery",
    "SearchRequest",
    "SearchResponse",
    "SearchResult",
    "TransientSearchHit",
    "classify",
    "classify_url",
]
