"""Dependency-light contracts shared by both Post-C effect paths."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol


class PostCPreregistrationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class PostCPreregistrationSeal:
    operation_id: str
    canonical_bytes: bytes
    preregistration_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.canonical_bytes) is not bytes
            or hashlib.sha256(self.canonical_bytes).hexdigest() != self.preregistration_sha256
        ):
            raise PostCPreregistrationError("post_c_seal_hash_mismatch")


class PrivateSealWriter(Protocol):
    approved_root: str

    def write(self, seal: PostCPreregistrationSeal) -> None: ...
    def read(self, operation_id: str) -> bytes | None: ...


__all__ = [
    "PostCPreregistrationError",
    "PostCPreregistrationSeal",
    "PrivateSealWriter",
]
