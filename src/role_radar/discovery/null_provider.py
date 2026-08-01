"""Proveedor por defecto: no hace ninguna búsqueda de red."""

from role_radar.discovery.protocols import SearchQuery, SearchResult


class NullSearchProvider:
    async def search(self, query: SearchQuery) -> list[SearchResult]:
        return []
