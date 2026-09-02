"""Pure, offline authorization boundary for the future R3 pilot operation.

This module intentionally has no filesystem, settings, database, or network imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final


class R3Operation(StrEnum):
    SYNTHETIC_OFFLINE = "synthetic-offline"
    REAL = "real"


class R3BlockCode(StrEnum):
    AUTHORIZATION_REQUIRED = "authorization_required"
    OPERATION_INVALID = "operation_invalid"
    BINDING_INVALID = "binding_invalid"
    EXPIRED = "authorization_expired"
    DESTINATION_INVALID = "destination_invalid"


PUBLIC_BLOCK_CODES: Final[frozenset[str]] = frozenset(code.value for code in R3BlockCode)


class R3AuthorizationError(ValueError):
    def __init__(self, code: R3BlockCode) -> None:
        self.code = code.value
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class R2GateFBinding:
    receipt_sha256: str
    manifest_sha256: str
    dataset_id: str
    pilot_sha256: str
    pilot_view_sha256: str
    profile_id: str
    profile_version: int
    profile_schema: int
    profile_sha256: str
    rubric_version: str
    protocol_version: str
    count: int
    destination: str
    capability_seal_sha256: str
    corpus_sha256: str | None = None
    holdout_sha256: str | None = None
    rubric_sha256: str | None = None
    code_commit: str | None = None
    alembic_head: str | None = None
    namespace: str | None = None
    capability_seal_hashes: tuple[str, ...] | None = None
    capability_artifact_counts: tuple[int, ...] | None = None
    pilot_group_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class R3Authorization:
    operation: R3Operation
    binding: R2GateFBinding
    expires_at: datetime | None = None
    synthetic_fixture: bool = False


def validate_authorization(
    authorization: R3Authorization,
    expected: R2GateFBinding,
    *,
    now: datetime | None = None,
) -> R2GateFBinding:
    """Validate an exact binding without reading or creating anything."""
    if not isinstance(authorization, R3Authorization):
        raise R3AuthorizationError(R3BlockCode.AUTHORIZATION_REQUIRED)
    if (
        authorization.operation is not R3Operation.SYNTHETIC_OFFLINE
        or not authorization.synthetic_fixture
    ):
        raise R3AuthorizationError(R3BlockCode.AUTHORIZATION_REQUIRED)
    check_time = now or datetime.now(UTC)
    if authorization.expires_at is not None and check_time >= authorization.expires_at:
        raise R3AuthorizationError(R3BlockCode.EXPIRED)
    actual = authorization.binding
    if actual.destination != expected.destination or not actual.destination.startswith(
        "synthetic://"
    ):
        raise R3AuthorizationError(R3BlockCode.DESTINATION_INVALID)
    if actual != expected or actual.count < 1:
        raise R3AuthorizationError(R3BlockCode.BINDING_INVALID)
    return actual


__all__ = [
    "PUBLIC_BLOCK_CODES",
    "R2GateFBinding",
    "R3Authorization",
    "R3AuthorizationError",
    "R3BlockCode",
    "R3Operation",
    "validate_authorization",
]
