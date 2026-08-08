"""Code-owned policies for bounded collection; Source cannot override these."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from role_radar.collectors.outcomes import CollectorFailureCode

MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class HttpPolicy:
    origin: str
    allowed_path_prefix: str
    allowed_query_keys: frozenset[str]
    allowed_query_values: Mapping[str, frozenset[str]] | None = None
    wire_limit_bytes: int = 8 * MIB
    decoded_limit_bytes: int = 8 * MIB
    gzip_expansion_ratio: int = 100
    gzip_ratio_floor_bytes: int = 1024
    source_deadline_seconds: float = 120.0
    max_retries: int = 2


@dataclass(frozen=True, slots=True)
class CollectionPolicy:
    http: HttpPolicy
    max_pages: int = 1
    max_items: int = 500
    batch_limit_bytes: int = 32 * MIB
    description_limit_bytes: int = 256 * 1024
    structured_data_limit_bytes: int = 64 * 1024
    json_max_depth: int = 32
    json_max_nodes: int = 100_000


GREENHOUSE_POLICY = CollectionPolicy(
    http=HttpPolicy(
        origin="https://boards-api.greenhouse.io",
        allowed_path_prefix="/v1/boards/",
        allowed_query_keys=frozenset({"content"}),
        allowed_query_values=MappingProxyType({"content": frozenset({"true"})}),
    )
)

RETRYABLE_FAILURES = frozenset(
    {
        CollectorFailureCode.CONNECT,
        CollectorFailureCode.READ,
        CollectorFailureCode.POOL,
        CollectorFailureCode.NETWORK,
    }
)
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


def retryable_for(code: CollectorFailureCode, status: int | None = None) -> bool:
    return code in RETRYABLE_FAILURES or status in RETRYABLE_STATUSES


class CollectionRunBudget:
    """In-memory wire-attempt budget shared by one collection stage."""

    def __init__(self, maximum: int = 100) -> None:
        if maximum < 0:
            raise ValueError("budget must be non-negative")
        self.maximum = maximum
        self.consumed = 0

    def acquire(self) -> bool:
        if self.consumed >= self.maximum:
            return False
        self.consumed += 1
        return True

    @property
    def remaining(self) -> int:
        return self.maximum - self.consumed
