"""Canonical, explicit source plans.  Plans are data, never ORM objects."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from role_radar.evaluation.controlled_acquisition.protocols import (
    ALLOWED_FAMILIES,
    ALLOWED_ORIGINS,
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
    profile_sha256: str | None = None
    profile_id: str | None = None
    profile_version: int | None = None
    profile_schema_version: int | None = None
    selection_as_of_utc: str | None = None
    jobicy_terms_sha256: str | None = None
    jobicy_reviewed_at: str | None = None
    jobicy_fair_use_ack: bool = False
    jobicy_destination_ack: bool = False
    jobicy_no_redistribution_ack: bool = False
    source_commit: str | None = None
    source_diff_sha256: str | None = None
    source_status_sha256: str | None = None
    alembic_head: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_version": self.plan_version,
            "lookback_days": self.lookback_days,
            "source_configs": [dict(item) for item in self.source_configs],
            "wire_attempt_cap": self.wire_attempt_cap,
            "query_template_hashes": list(self.query_template_hashes),
            "allowed_origins": list(self.allowed_origins),
            "profile_sha256": self.profile_sha256,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_schema_version": self.profile_schema_version,
            "selection_as_of_utc": self.selection_as_of_utc,
            "jobicy_terms_sha256": self.jobicy_terms_sha256,
            "jobicy_reviewed_at": self.jobicy_reviewed_at,
            "jobicy_fair_use_ack": self.jobicy_fair_use_ack,
            "jobicy_destination_ack": self.jobicy_destination_ack,
            "jobicy_no_redistribution_ack": self.jobicy_no_redistribution_ack,
            "source_commit": self.source_commit,
            "source_diff_sha256": self.source_diff_sha256,
            "source_status_sha256": self.source_status_sha256,
            "alembic_head": self.alembic_head,
        }

    @property
    def sha256(self) -> str:
        return canonical_sha256(self.as_dict())


_PLAN_KEYS = frozenset(
    {
        "plan_version",
        "lookback_days",
        "source_configs",
        "wire_attempt_cap",
        "query_template_hashes",
        "allowed_origins",
        "profile_sha256",
        "profile_id",
        "profile_version",
        "profile_schema_version",
        "selection_as_of_utc",
        "jobicy_terms_sha256",
        "jobicy_reviewed_at",
        "jobicy_fair_use_ack",
        "jobicy_destination_ack",
        "jobicy_no_redistribution_ack",
        "source_commit",
        "source_diff_sha256",
        "source_status_sha256",
        "alembic_head",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "family",
        "source_id",
        "source_key",
        "revision",
        "configuration_version",
        "configuration",
    }
)


def load_plan(value: Mapping[str, Any]) -> SourcePlan:
    if set(value) != _PLAN_KEYS:
        raise PlanError("plan_fields_invalid")
    source_configs = value.get("source_configs")
    if not isinstance(source_configs, (list, tuple)):
        raise PlanError("source_configs_invalid")
    if any(
        not isinstance(item, Mapping)
        or any(
            key not in _SOURCE_KEYS
            for key in item
            if key.lower().replace("-", "_").endswith(("token", "secret", "password"))
        )
        or set(item) != _SOURCE_KEYS
        for item in source_configs
    ):
        if any(
            isinstance(item, Mapping)
            and any(
                key.lower().replace("-", "_").endswith(("token", "secret", "password"))
                for key in item
            )
            for item in source_configs
        ):
            raise PlanError("source_plan_secret_field")
        raise PlanError("source_fields_invalid")
    plan = SourcePlan(
        plan_version=str(value.get("plan_version", "")),
        lookback_days=value.get("lookback_days", -1),
        source_configs=tuple(source_configs),
        wire_attempt_cap=value.get("wire_attempt_cap", MAX_WIRE_ATTEMPTS),
        query_template_hashes=tuple(value.get("query_template_hashes", ())),
        allowed_origins=tuple(value.get("allowed_origins", ())),
        profile_sha256=value.get("profile_sha256"),
        profile_id=value.get("profile_id"),
        profile_version=value.get("profile_version"),
        profile_schema_version=value.get("profile_schema_version"),
        selection_as_of_utc=value.get("selection_as_of_utc"),
        jobicy_terms_sha256=value.get("jobicy_terms_sha256"),
        jobicy_reviewed_at=value.get("jobicy_reviewed_at"),
        jobicy_fair_use_ack=value.get("jobicy_fair_use_ack", False),
        jobicy_destination_ack=value.get("jobicy_destination_ack", False),
        jobicy_no_redistribution_ack=value.get("jobicy_no_redistribution_ack", False),
        source_commit=value.get("source_commit"),
        source_diff_sha256=value.get("source_diff_sha256"),
        source_status_sha256=value.get("source_status_sha256"),
        alembic_head=value.get("alembic_head"),
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
    if any(origin not in ALLOWED_ORIGINS for origin in plan.allowed_origins):
        raise PlanError("origin_not_allowed")
    family_counts: dict[str, int] = {}
    for source in plan.source_configs:
        family = source.get("family")
        if family not in ALLOWED_FAMILIES:
            raise PlanError("source_family_invalid")
        family_counts[family] = family_counts.get(family, 0) + 1
        if family_counts[family] > 10:
            raise PlanError("source_family_config_limit")
        if (
            not isinstance(source.get("source_id"), str)
            or not source["source_id"]
            or not isinstance(source.get("revision"), int)
            or isinstance(source["revision"], bool)
            or source["revision"] < 1
        ):
            raise PlanError("source_snapshot_incomplete")
        secret_markers = (
            "api_key",
            "apikey",
            "token",
            "secret",
            "password",
            "credential",
            "authorization",
            "cookie",
        )
        if any(
            any(
                key.lower().replace("-", "_") == marker
                or key.lower().replace("-", "_").endswith(f"_{marker}")
                for marker in secret_markers
            )
            for key in source
        ):
            raise PlanError("source_plan_secret_field")
    if any(
        not isinstance(value, str) or len(value) != 64
        for value in plan.query_template_hashes
    ):
        raise PlanError("query_template_hash_invalid")


def validate_live_plan(plan: SourcePlan) -> datetime:
    """Validate the identity required before a network-capable run."""
    if plan.profile_sha256 is None or len(plan.profile_sha256) != 64:
        raise PlanError("profile_hash_required")
    if any(char not in "0123456789abcdef" for char in plan.profile_sha256):
        raise PlanError("profile_hash_invalid")
    if (
        not isinstance(plan.profile_id, str)
        or not plan.profile_id
        or not isinstance(plan.profile_version, int)
        or isinstance(plan.profile_version, bool)
        or plan.profile_version < 1
        or plan.profile_schema_version != 1
    ):
        raise PlanError("profile_identity_required")
    if plan.selection_as_of_utc is None:
        raise PlanError("selection_as_of_required")
    try:
        as_of = datetime.fromisoformat(plan.selection_as_of_utc.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanError("selection_as_of_invalid") from exc
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise PlanError("selection_as_of_invalid")
    if as_of.astimezone(UTC).microsecond:
        raise PlanError("selection_as_of_precision")
    if not plan.source_configs:
        raise PlanError("source_plan_empty")
    empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if (
        not isinstance(plan.source_commit, str)
        or len(plan.source_commit) != 40
        or any(char not in "0123456789abcdef" for char in plan.source_commit)
        or plan.source_diff_sha256 != empty_sha
        or plan.source_status_sha256 != empty_sha
        or plan.alembic_head != "e7a4c9f1b2d3"
    ):
        raise PlanError("deployment_provenance_required")
    has_jobicy = any(item.get("family") == "jobicy" for item in plan.source_configs)
    if has_jobicy and (
        not isinstance(plan.jobicy_terms_sha256, str)
        or len(plan.jobicy_terms_sha256) != 64
        or any(char not in "0123456789abcdef" for char in plan.jobicy_terms_sha256)
        or not isinstance(plan.jobicy_reviewed_at, str)
        or not plan.jobicy_fair_use_ack
        or not plan.jobicy_destination_ack
        or not plan.jobicy_no_redistribution_ack
    ):
        raise PlanError("jobicy_terms_ack_required")
    if not plan.allowed_origins:
        raise PlanError("origins_required")
    if set(plan.allowed_origins) != set(ALLOWED_ORIGINS):
        raise PlanError("origins_incomplete")
    for source in plan.source_configs:
        if not isinstance(source.get("source_key"), str) or not source["source_key"]:
            raise PlanError("source_key_required")
        if source.get("configuration_version") != 1:
            raise PlanError("configuration_version_required")
        if not isinstance(source.get("configuration"), Mapping):
            raise PlanError("source_configuration_required")
    return as_of.astimezone(UTC)
