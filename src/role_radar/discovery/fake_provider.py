"""Proveedor configurable para tests y desarrollo offline."""

from collections.abc import Iterable

from role_radar.discovery.protocols import SearchQuery, SearchResult


class FakeSearchProvider:
    def __init__(self, results: Iterable[SearchResult] = ()) -> None:
        self.results = list(results)
        self.queries: list[SearchQuery] = []

    async def search(self, query: SearchQuery) -> list[SearchResult]:
        self.queries.append(query)
        return list(self.results)
