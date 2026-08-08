"""Provider-neutral RawJob and canonical batch bounds."""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from role_radar.collectors.bounded_json import canonical_json_bytes, validate_tree
from role_radar.domain.dto import RawJob


class RawJobBoundsError(ValueError):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(kind)


def _text(value: str | None, limit: int | None = None, *, reject_controls: bool = False) -> None:
    if value is None:
        return
    if reject_controls and any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise RawJobBoundsError("invalid")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeEncodeError as exc:
        raise RawJobBoundsError("invalid") from exc
    if limit is not None and size > limit:
        raise RawJobBoundsError("oversized")


def validate_url(value: str | None, *, max_bytes: int = 2048) -> None:
    if value is None:
        return
    _text(value, max_bytes, reject_controls=True)
    if any(char.isspace() for char in value):
        raise RawJobBoundsError("invalid")
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise RawJobBoundsError("invalid")
        if parsed.username is not None or parsed.password is not None:
            raise RawJobBoundsError("invalid")
    except ValueError as exc:
        raise RawJobBoundsError("invalid") from exc


def validate_raw_job(
    job: RawJob,
    *,
    description_limit_bytes: int = 256 * 1024,
    structured_data_limit_bytes: int = 64 * 1024,
    max_depth: int = 32,
) -> bytes:
    """Validate without truncating; return its deterministic canonical bytes."""
    _text(job.source)
    _text(job.external_id, 255)
    _text(job.title, 255)
    _text(job.company, 255)
    _text(job.location, 255)
    _text(job.description, description_limit_bytes)
    validate_url(job.source_url)
    validate_url(job.application_url)
    validate_tree(job.structured_data, max_depth=max_depth)
    structured = canonical_json_bytes(job.structured_data)
    if len(structured) > structured_data_limit_bytes:
        raise RawJobBoundsError("oversized")
    try:
        canonical = canonical_json_bytes(job.model_dump(mode="json"))
    except Exception as exc:
        raise RawJobBoundsError("invalid") from exc
    return canonical


@dataclass(slots=True)
class CanonicalBatch:
    limit_bytes: int = 32 * 1024 * 1024
    _size: int = 2
    _items: int = 0

    def add(self, canonical_job: bytes) -> int:
        next_size = self._size + (1 if self._items else 0) + len(canonical_job)
        if next_size > self.limit_bytes:
            raise RawJobBoundsError("batch")
        self._size = next_size
        self._items += 1
        return self._size

    @property
    def size(self) -> int:
        return self._size


def build_raw_job(values: dict[str, Any], **kwargs: Any) -> tuple[RawJob, bytes]:
    try:
        job = RawJob.model_validate(values)
    except ValidationError as exc:
        raise RawJobBoundsError("invalid") from exc
    return job, validate_raw_job(job, **kwargs)
