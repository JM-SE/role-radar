"""Owned, fixed-origin search provider adapters."""

from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider

__all__ = ["BraveSearchProvider", "TavilySearchProvider"]
