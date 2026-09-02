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


# This is an offline, test-only Gate F identity.  It is deliberately an exact
# immutable fixture rather than a value derived from the publication supplied
# by a caller.  It is not an approval root for production data.
SYNTHETIC_GATE_F_TRUST_ANCHOR: Final[R2GateFBinding] = R2GateFBinding(
    receipt_sha256="5d440b22e6d1608c6a56ffeb9a10e0e3ad8a37d35846b8565ee851172c0a1cf5",
    manifest_sha256="47135db85a534eea904359f292a919dbb8fcb830d83dd03ba45988a6980d31ab",
    dataset_id="c" * 64,
    pilot_sha256="d" * 64,
    pilot_view_sha256="a25066ca8293d77c949a4d64bce857984c7b318ca886ed18efc501853bfc1783",
    profile_id="synthetic-profile",
    profile_version=1,
    profile_schema=1,
    profile_sha256="f" * 64,
    rubric_version="synthetic-rubric",
    protocol_version="synthetic-protocol",
    count=2,
    destination="synthetic://r2-gate-f/pilot",
    capability_seal_sha256="1" * 64,
    corpus_sha256="2" * 64,
    holdout_sha256="3" * 64,
    rubric_sha256="bf6421ccda2dcb3a7ef5bf64a5007c7f4e7b56ea02d4bc58853a16a13dc55fbf",
    code_commit="4" * 64,
    alembic_head="5" * 64,
    namespace="synthetic://r2-gate-f/pilot",
    capability_seal_hashes=(
        "65cc947f7317f6015ccecfe5962972a5b67de20df11e83c10e2bc2e1e828434d",
        "bde2f76be06bc86f14575114258c3e4ae2532fc4a84cf1a149a8c35c60561060",
        "96d8beb0f899d820e7c1d7c7b3ef57b7df2ab476947417d2b8bd61a00de1ecf5",
    ),
    capability_artifact_counts=(1, 1, 1),
    pilot_group_sha256="a25066ca8293d77c949a4d64bce857984c7b318ca886ed18efc501853bfc1783",
)


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
    "SYNTHETIC_GATE_F_TRUST_ANCHOR",
    "R2GateFBinding",
    "R3Authorization",
    "R3AuthorizationError",
    "R3BlockCode",
    "R3Operation",
    "validate_authorization",
]
