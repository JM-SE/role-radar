"""Offline-only F10.1F CLI boundary.

Live network, database, systemd, and holdout operations intentionally have no
entry point in this refactor.  The command reports a stable blocked result
until the focused package is wired by a separately approved execution task.
"""

from __future__ import annotations

import json
from typing import Any


def run(args: Any) -> int:
    """Reject live-gate execution without touching external systems."""

    _ = args
    print(json.dumps({"result": "blocked", "code": "f10_1f_live_execution_disabled"}))
    return 2


__all__ = ["run"]
