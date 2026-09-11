"""Dependency-light seed DTO shared by source-plan boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass

HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class SeedInputsError(ValueError):
    """Stable error for malformed seed inputs."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SeedInputs:
    """The only acceptable seed input: exactly two distinct 32-byte values."""

    selection_seed: str
    partition_seed: str

    def __post_init__(self) -> None:
        for field in ("selection_seed", "partition_seed"):
            value = getattr(self, field)
            if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
                raise SeedInputsError(f"{field}_invalid")
        if self.selection_seed == self.partition_seed:
            raise SeedInputsError("seeds_must_differ")


__all__ = ["SeedInputs", "SeedInputsError"]
