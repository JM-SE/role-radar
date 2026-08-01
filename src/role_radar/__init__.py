"""role-radar — pipeline personal de búsqueda laboral."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("role-radar")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"
