"""Fail-closed F10.1F operational policy.

There are intentionally no seed, namespace, root, or approval defaults in
this module.  Values must arrive through a typed artifact or an explicitly
synthetic test input.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Final

from role_radar.evaluation.profile_relevant_acquisition.seed_inputs import SeedInputs

SEED_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
MAX_PER_BOARD_CAP: Final[int] = 100_000
MAX_QUOTA_ROWS: Final[int] = 10_000
PASSED_STATUS: Final[str] = "passed"
STALE_STATUS: Final[str] = "stale"
NON_EXECUTABLE_STATUS: Final[str] = "non_executable"
BLOCK_0: Final[str] = "BLOCK-0"


class PolicyError(ValueError):
    """Stable sanitized policy failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_seed(value: object, *, field: str) -> str:
    """Validate one explicit 64 lowercase-hex seed without generating it."""

    code = f"{field}_invalid"
    if not isinstance(value, str) or SEED_RE.fullmatch(value) is None:
        raise PolicyError(code)
    return value


def validate_seed_pair(selection_seed: object, partition_seed: object) -> SeedInputs:
    """Return a typed pair only when both explicit seeds are valid and distinct."""

    selection = validate_seed(selection_seed, field="selection_seed")
    partition = validate_seed(partition_seed, field="partition_seed")
    if selection == partition:
        raise PolicyError("seeds_must_differ")
    try:
        return SeedInputs(selection_seed=selection, partition_seed=partition)
    except (TypeError, ValueError) as exc:
        raise PolicyError("seeds_must_differ") from exc


def validate_seed_inputs(value: object) -> SeedInputs:
    """Validate the non-coercible seed DTO at a runtime boundary."""

    if not isinstance(value, SeedInputs):
        raise PolicyError("seed_inputs_invalid")
    return validate_seed_pair(value.selection_seed, value.partition_seed)


def validate_hash(value: object, *, code: str = "policy_hash_invalid") -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise PolicyError(code)
    return value


def validate_quota_cap(total: object, per_board_cap: object) -> None:
    """Enforce a non-negative row total against the approved board cap."""

    if (
        not isinstance(per_board_cap, int)
        or isinstance(per_board_cap, bool)
        or per_board_cap <= 0
        or per_board_cap > MAX_PER_BOARD_CAP
    ):
        raise PolicyError("per_board_cap_invalid")
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise PolicyError("quota_total_invalid")
    if total > per_board_cap:
        raise PolicyError("quota_exceeds_per_board_cap")


def validate_quota_totals(
    totals: Mapping[str, int] | Iterable[tuple[str, int]], *, per_board_cap: int
) -> None:
    """Validate every source/board total; examples cannot bypass this check."""

    validate_quota_cap(0, per_board_cap)
    rows = totals.items() if isinstance(totals, Mapping) else totals
    seen: set[str] = set()
    for count, (source, total) in enumerate(rows, start=1):
        if count > MAX_QUOTA_ROWS:
            raise PolicyError("quota_rows_exceeded")
        if not isinstance(source, str) or not source.strip():
            raise PolicyError("quota_source_invalid")
        if source in seen:
            raise PolicyError("quota_source_duplicate")
        seen.add(source)
        validate_quota_cap(total, per_board_cap)


def validate_decision_status(status: object) -> None:
    """Only an explicit approved status may be considered executable."""

    if status == STALE_STATUS:
        raise PolicyError("decision_stale")
    if status == NON_EXECUTABLE_STATUS:
        raise PolicyError("decision_non_executable")
    if status != "approved":
        raise PolicyError("decision_not_approved")


def validate_prerequisite_status(status: object) -> None:
    if status != PASSED_STATUS:
        if status == STALE_STATUS:
            raise PolicyError("prerequisite_stale")
        if status in {"failed", "pending", "blocked"}:
            raise PolicyError("prerequisite_not_terminal")
        raise PolicyError("prerequisite_status_invalid")


__all__ = [
    "BLOCK_0",
    "HASH_RE",
    "MAX_PER_BOARD_CAP",
    "MAX_QUOTA_ROWS",
    "NON_EXECUTABLE_STATUS",
    "PASSED_STATUS",
    "SEED_RE",
    "STALE_STATUS",
    "PolicyError",
    "validate_decision_status",
    "validate_hash",
    "validate_prerequisite_status",
    "validate_quota_cap",
    "validate_quota_totals",
    "validate_seed",
    "validate_seed_inputs",
    "validate_seed_pair",
]
