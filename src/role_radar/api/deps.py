"""Dependencias FastAPI inyectables (seam para tests)."""

from role_radar.config import Settings, get_settings

__all__ = ["Settings", "get_settings"]
