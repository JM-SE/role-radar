"""Strict, dedicated configuration for F10.1.

The application settings deliberately do not provide a default for this
variable.  A live operation must opt in through its own environment file.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from role_radar.evaluation.controlled_acquisition.protocols import DEFAULT_SNAPSHOT_ROOT

LOOKBACK_ENV = "ROLE_RADAR_F10_1_LOOKBACK_DAYS"


class ConfigurationError(ValueError):
    """A missing or unsafe F10.1 configuration value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def parse_lookback_days(environ: Mapping[str, str] | None = None) -> int:
    values = os.environ if environ is None else environ
    raw = values.get(LOOKBACK_ENV)
    if raw is None:
        raise ConfigurationError("lookback_missing")
    if not raw or raw != raw.strip() or not raw.isascii() or not raw.isdigit():
        raise ConfigurationError("lookback_not_strict_integer")
    value = int(raw)
    if not 1 <= value <= 30:
        raise ConfigurationError("lookback_out_of_range")
    return value


@dataclass(frozen=True, slots=True)
class FrozenWindow:
    selection_as_of_utc: datetime
    cutoff_utc: datetime
    lookback_days: int

    def __post_init__(self) -> None:
        for value in (self.selection_as_of_utc, self.cutoff_utc):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("window timestamps must be timezone-aware")
        expected_cutoff = self.selection_as_of_utc.astimezone(UTC) - timedelta(
            days=self.lookback_days
        )
        if expected_cutoff != self.cutoff_utc.astimezone(UTC):
            raise ValueError("window cutoff does not match lookback")


def freeze_window(*, selection_as_of_utc: datetime, lookback_days: int) -> FrozenWindow:
    if not 1 <= lookback_days <= 30:
        raise ConfigurationError("lookback_out_of_range")
    as_of = selection_as_of_utc.astimezone(UTC).replace(microsecond=0)
    return FrozenWindow(as_of, as_of - timedelta(days=lookback_days), lookback_days)


@dataclass(frozen=True, slots=True)
class ControlledAcquisitionConfig:
    lookback_days: int
    snapshot_root: str = DEFAULT_SNAPSHOT_ROOT
    max_wire_attempts: int = 100
    future_tolerance_seconds: int = 300

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        snapshot_root: str = DEFAULT_SNAPSHOT_ROOT,
    ) -> ControlledAcquisitionConfig:
        return cls(lookback_days=parse_lookback_days(environ), snapshot_root=snapshot_root)

    def require_approved_run(self) -> None:
        if self.lookback_days != 14:
            raise ConfigurationError("lookback_requires_new_approved_plan")

    def window(self, selection_as_of_utc: datetime) -> FrozenWindow:
        return freeze_window(
            selection_as_of_utc=selection_as_of_utc,
            lookback_days=self.lookback_days,
        )
