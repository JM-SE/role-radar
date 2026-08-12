"""Canonical, explicit source plans.  Plans are data, never ORM objects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from role_radar.evaluation.controlled_acquisition.protocols import (
    ALLOWED_FAMILIES,
    MAX_WIRE_ATTEMPTS,
    PLAN_VERSION,
)


class PlanError(ValueError):
    """An unsafe or non-canonical F10.1 plan."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class SourcePlan:
    plan_version: str
    lookback_days: int
    source_configs: tuple[Mapping[str, Any], ...]
    wire_attempt_cap: int = MAX_WIRE_ATTEMPTS
    query_template_hashes: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_version": self.plan_version,
            "lookback_days": self.lookback_days,
            "source_configs": [dict(item) for item in self.source_configs],
            "wire_attempt_cap": self.wire_attempt_cap,
            "query_template_hashes": list(self.query_template_hashes),
            "allowed_origins": list(self.allowed_origins),
        }

    @property
    def sha256(self) -> str:
        return canonical_sha256(self.as_dict())


def load_plan(value: Mapping[str, Any]) -> SourcePlan:
    plan = SourcePlan(
        plan_version=str(value.get("plan_version", "")),
        lookback_days=value.get("lookback_days", -1),
        source_configs=tuple(value.get("source_configs", ())),
        wire_attempt_cap=value.get("wire_attempt_cap", MAX_WIRE_ATTEMPTS),
        query_template_hashes=tuple(value.get("query_template_hashes", ())),
        allowed_origins=tuple(value.get("allowed_origins", ())),
    )
    validate_plan(plan)
    return plan


def validate_plan(plan: SourcePlan) -> None:
    if plan.plan_version != PLAN_VERSION:
        raise PlanError("plan_version_invalid")
    if plan.lookback_days != 14:
        raise PlanError("lookback_must_be_14")
    if not 1 <= plan.wire_attempt_cap <= MAX_WIRE_ATTEMPTS:
        raise PlanError("wire_attempt_cap_invalid")
    if len(plan.source_configs) > 30:
        raise PlanError("source_config_limit")
    for source in plan.source_configs:
        family = source.get("family")
        if family not in ALLOWED_FAMILIES:
            raise PlanError("source_family_invalid")
        if "source_id" not in source or "revision" not in source:
            raise PlanError("source_snapshot_incomplete")
        secret_markers = ("token", "secret", "password", "key")
        if any(
            key.lower().endswith(marker) for key in source for marker in secret_markers
        ):
            raise PlanError("source_plan_secret_field")
    if any(
        not isinstance(value, str) or len(value) != 64
        for value in plan.query_template_hashes
    ):
        raise PlanError("query_template_hash_invalid")
