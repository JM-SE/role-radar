"""Proveedor por defecto: no hace ninguna búsqueda de red."""

from typing import overload

from role_radar.discovery.contracts import ProviderTier, SearchRequest, SearchResponse
from role_radar.discovery.protocols import SearchQuery, SearchResult


class NullSearchProvider:
    @overload
    async def search(self, query: SearchRequest) -> SearchResponse: ...

    @overload
    async def search(self, query: SearchQuery) -> list[SearchResult]: ...

    async def search(
        self, query: SearchRequest | SearchQuery
    ) -> SearchResponse | list[SearchResult]:
        if isinstance(query, SearchQuery):
            return []
        return SearchResponse(provider="brave", tier=ProviderTier.FREE, status="empty")

    async def aclose(self) -> None:
        return None
