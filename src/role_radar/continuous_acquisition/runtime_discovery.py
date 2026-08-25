"""Fail-closed compatibility boundary for the historical discovery command.

F10.1D owns the dedicated ``continuous-discovery-v2`` path.  The old command
remains parseable for operators and old unit files, but it must not load
configuration, credentials, a database, a provider, or a service runtime.
"""

from __future__ import annotations

from role_radar.continuous_acquisition.runtime_support import (
    EXIT_PRECONDITION,
    RuntimeResult,
)

DISCOVERY_V2_COMMAND_REQUIRED = "discovery_v2_command_required"


def run_discovery_once(*_args: object, **_kwargs: object) -> RuntimeResult:
    """Return the sanitized deprecation result without any side effect."""

    return RuntimeResult(
        {
            "schema_version": "continuous-discovery-v2-result-v1",
            "result": "blocked",
            "code": DISCOVERY_V2_COMMAND_REQUIRED,
        },
        EXIT_PRECONDITION,
    )


__all__ = ["DISCOVERY_V2_COMMAND_REQUIRED", "run_discovery_once"]
