"""Sanitized, immutable outcomes shared by collection adapters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from role_radar.domain.dto import RawJob


class CollectorFailureCode(StrEnum):
    CONFIG = "config"
    ORIGIN = "origin"
    DEADLINE = "deadline"
    CONNECT = "connect"
    READ = "read"
    POOL = "pool"
    NETWORK = "network"
    TLS = "tls"
    REDIRECT = "redirect"
    RATE_LIMITED = "rate_limited"
    UPSTREAM = "upstream"
    CLIENT_STATUS = "client_status"
    CONTENT_TYPE = "content_type"
    CONTENT_ENCODING = "content_encoding"
    RESPONSE_TOO_LARGE = "response_too_large"
    DECOMPRESSION = "decompression"
    INVALID_JSON = "invalid_json"
    PAYLOAD_INVALID = "payload_invalid"
    REQUEST_BUDGET = "request_budget"
    PAGE_LIMIT = "page_limit"
    JOB_LIMIT = "job_limit"
    BATCH_LIMIT = "batch_limit"
    NO_VALID_ITEMS = "no_valid_items"
    INTERNAL = "internal"
    PERSISTENCE = "persistence"


class CollectionStopCode(StrEnum):
    RETRIES_EXHAUSTED = "retries_exhausted"
    DEADLINE_EXPIRED = "deadline_expired"
    REQUEST_BUDGET_EXHAUSTED = "request_budget_exhausted"
    RESPONSE_LIMIT = "response_limit"
    DECOMPRESSION_LIMIT = "decompression_limit"
    PAGE_LIMIT_REACHED = "page_limit_reached"
    JOB_LIMIT_REACHED = "job_limit_reached"
    BATCH_LIMIT_REACHED = "batch_limit_reached"
    INVALID_PAYLOAD = "invalid_payload"
    NO_VALID_ITEMS = "no_valid_items"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True, slots=True)
class RejectionCounts:
    invalid_item: int = 0
    oversized_item: int = 0
    duplicate_identical: int = 0
    duplicate_conflict: int = 0

    def __post_init__(self) -> None:
        if any(
            value < 0
            for value in (
                self.invalid_item,
                self.oversized_item,
                self.duplicate_identical,
                self.duplicate_conflict,
            )
        ):
            raise ValueError("rejection counts must be non-negative")

    @property
    def rejected_items(self) -> int:
        return self.invalid_item + self.oversized_item + self.duplicate_conflict

    @property
    def duplicate_items(self) -> int:
        return self.duplicate_identical + self.duplicate_conflict


@dataclass(frozen=True, slots=True)
class CollectionMetrics:
    logical_requests: int = 0
    logical_pages: int = 0
    wire_attempts: int = 0
    retries: int = 0
    wire_bytes: int = 0
    decoded_bytes: int = 0
    provider_items: int = 0
    overflow_probe_items: int = 0
    accepted_items: int = 0
    rejected_items: int = 0
    duplicate_items: int = 0
    canonical_batch_bytes: int = 0
    duration_seconds: float = 0.0

    def __post_init__(self) -> None:
        values = (
            self.logical_requests,
            self.logical_pages,
            self.wire_attempts,
            self.retries,
            self.wire_bytes,
            self.decoded_bytes,
            self.provider_items,
            self.overflow_probe_items,
            self.accepted_items,
            self.rejected_items,
            self.duplicate_items,
            self.canonical_batch_bytes,
            self.duration_seconds,
        )
        if any(value < 0 for value in values):
            raise ValueError("collection metrics must be non-negative")


def _validate_common(metrics: CollectionMetrics, rejections: RejectionCounts) -> None:
    if metrics.provider_items != (
        metrics.accepted_items
        + rejections.invalid_item
        + rejections.oversized_item
        + rejections.duplicate_identical
        + rejections.duplicate_conflict
    ):
        raise ValueError("provider item conservation invariant violated")
    if metrics.accepted_items < 0 or metrics.rejected_items != rejections.rejected_items:
        raise ValueError("rejection accounting invariant violated")
    if metrics.duplicate_items != rejections.duplicate_items:
        raise ValueError("duplicate accounting invariant violated")


@dataclass(frozen=True, slots=True)
class CollectionSuccess:
    status: Literal["ok", "partial"]
    jobs: tuple[RawJob, ...]
    metrics: CollectionMetrics
    rejection_counts: RejectionCounts = RejectionCounts()
    stop_code: CollectionStopCode | None = None

    def __post_init__(self) -> None:
        if self.status not in {"ok", "partial"}:
            raise ValueError("invalid collection success status")
        if self.metrics.accepted_items != len(self.jobs):
            raise ValueError("accepted item count must equal job count")
        _validate_common(self.metrics, self.rejection_counts)
        if self.status == "partial" and not self.jobs:
            raise ValueError("partial collection requires at least one job")


@dataclass(frozen=True, slots=True)
class CollectionFailure:
    status: Literal["failed"]
    error_code: CollectorFailureCode
    metrics: CollectionMetrics
    rejection_counts: RejectionCounts = RejectionCounts()
    retryable: bool = False
    http_status: int | None = None
    stop_code: CollectionStopCode | None = None

    def __post_init__(self) -> None:
        if self.status != "failed":
            raise ValueError("invalid collection failure status")
        if self.http_status is not None and not 100 <= self.http_status <= 599:
            raise ValueError("invalid HTTP status")
        if self.metrics.accepted_items != 0:
            raise ValueError("failed collection cannot contain accepted jobs")
        _validate_common(self.metrics, self.rejection_counts)


CollectionOutcome = CollectionSuccess | CollectionFailure
