"""Public, ORM-free contracts for source metadata."""

from dataclasses import dataclass
from enum import StrEnum

from role_radar.domain.enums import SourceType


class AuthMode(StrEnum):
    NONE = "none"
    FUTURE = "future"


class PagingMode(StrEnum):
    NONE = "none"
    PAGE = "page"
    OFFSET = "offset"


@dataclass(frozen=True)
class ResourceBounds:
    """Declared limits. Quantitative enforcement is deliberately F8.2."""

    max_pages: int | None = None
    max_items: int | None = None
    max_bytes: int | None = None
    max_duration_seconds: float | None = None
    enforced: bool = False


@dataclass(frozen=True)
class SourceCatalogEntry:
    source_type: SourceType
    display_name: str
    docs_url: str
    adapter_available: bool
    configuration_model: str | None
    configuration_version: int | None
    factory_ref: str | None
    canonicalizer_ref: str | None
    auth_mode: AuthMode
    allowed_origins: tuple[str, ...]
    paging: PagingMode
    notes: str
    resource_bounds: ResourceBounds
    terms_policy_version: str | None = None


@dataclass(frozen=True)
class PublicSourceConfiguration:
    board_token: str | None = None
    company: str | None = None

    def as_dict(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if self.board_token is not None:
            result["board_token"] = self.board_token
        if self.company is not None:
            result["company"] = self.company
        return result


@dataclass(frozen=True)
class PublicLeverSourceConfiguration:
    site: str
    region: str
    company: str | None = None

    def as_dict(self) -> dict[str, str]:
        result = {"site": self.site, "region": self.region}
        if self.company is not None:
            result["company"] = self.company
        return result


@dataclass(frozen=True)
class PublicJobicySourceConfiguration:
    region: str
    remote_only: str
    configuration_version: str

    def as_dict(self) -> dict[str, str]:
        return {
            "region": self.region,
            "remote_only": self.remote_only,
            "configuration_version": self.configuration_version,
        }
