"""Read-only filesystem boundary for recovered Gate E preflight inputs."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .post_c_recovery_filesystem import (
    MAX_JSON_BYTES,
    RecoveryFilesystemError,
    list_children,
    pinned_root,
    read_json,
    validate_pinned_root,
)

ARTIFACT_NAMES = frozenset(
    {"journal.json", "checkpoint.json", "evidence.json", "parent-pool.json", "manifest.json"}
)


class RecoveredGateEPreflightFilesystemError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@contextmanager
def pinned_input_roots(roots: tuple[Path, ...]) -> Iterator[tuple[int, ...]]:
    """Keep all four approved roots pinned for the complete read transaction."""

    if len(roots) != 4:
        raise RecoveredGateEPreflightFilesystemError("gate_e_preflight_root_invalid")
    try:
        with (
            pinned_root(roots[0]) as first,
            pinned_root(roots[1]) as second,
            pinned_root(roots[2]) as third,
            pinned_root(roots[3]) as fourth,
        ):
            pinned = (first, second, third, fourth)
            identities = tuple(validate_pinned_root(fd) for fd in pinned)
            yield pinned
            if tuple(validate_pinned_root(fd) for fd in pinned) != identities:
                raise RecoveredGateEPreflightFilesystemError("gate_e_preflight_root_replaced")
    except (RecoveryFilesystemError, OSError) as exc:
        raise RecoveredGateEPreflightFilesystemError("gate_e_preflight_filesystem_invalid") from exc


def read_gate_d_artifacts(root_fd: int, root: Path) -> dict[str, tuple[dict[str, Any], bytes]]:
    try:
        if set(list_children(root_fd)) != set(ARTIFACT_NAMES):
            raise RecoveredGateEPreflightFilesystemError("gate_e_preflight_artifact_set_invalid")
        output: dict[str, tuple[dict[str, Any], bytes]] = {}
        for name in sorted(ARTIFACT_NAMES):
            output[name] = read_json(
                root_fd,
                root,
                root / name,
                maximum=MAX_JSON_BYTES,
                require_object=name not in {"journal.json", "parent-pool.json"},
            )
        if set(list_children(root_fd)) != set(ARTIFACT_NAMES):
            raise RecoveredGateEPreflightFilesystemError("gate_e_preflight_artifact_set_invalid")
        return output
    except RecoveredGateEPreflightFilesystemError:
        raise
    except (RecoveryFilesystemError, OSError) as exc:
        raise RecoveredGateEPreflightFilesystemError("gate_e_preflight_artifact_invalid") from exc


__all__ = [
    "ARTIFACT_NAMES",
    "RecoveredGateEPreflightFilesystemError",
    "pinned_input_roots",
    "read_gate_d_artifacts",
]
