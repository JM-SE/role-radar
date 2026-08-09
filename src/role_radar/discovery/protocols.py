"""Contratos del proveedor de búsqueda usado solo por discover-boards."""

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class SearchQuery(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    query: str
    max_results: int = Field(default=10, gt=0)


class SearchResult(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    title: str
    url: str
    snippet: str | None = None


class SearchProvider(Protocol):
    async def search(self, query: SearchQuery) -> list[SearchResult]: ...
