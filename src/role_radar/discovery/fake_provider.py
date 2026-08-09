"""Proveedor configurable para tests y desarrollo offline."""

from collections.abc import Iterable
from typing import overload

from role_radar.discovery.contracts import (
    ProviderTier,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
)
from role_radar.discovery.protocols import SearchQuery, SearchResult


class FakeSearchProvider:
    def __init__(self, results: Iterable[SearchResult] = ()) -> None:
        self.results = list(results)
        self.queries: list[SearchQuery] = []

    @overload
    async def search(self, query: SearchRequest) -> SearchResponse: ...

    @overload
    async def search(self, query: SearchQuery) -> list[SearchResult]: ...

    async def search(
        self, query: SearchRequest | SearchQuery
    ) -> SearchResponse | list[SearchResult]:
        if isinstance(query, SearchQuery):
            self.queries.append(query)
            return list(self.results[: query.max_results])
        hits = tuple(
            TransientSearchHit(url=result.url, rank=index)
            for index, result in enumerate(self.results[: query.max_results], start=1)
        )
        return SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="succeeded" if hits else "empty",
            hits=hits,
            result_count=len(hits),
        )

    async def aclose(self) -> None:
        return None
