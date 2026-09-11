"""Strict F10.1F source-plan DTO.

This module deliberately does not re-export the historical controlled-acquisition
``SourcePlan``.  A plan entering Gate D is a complete, immutable F10.1F record;
the exact canonical bytes supplied to the collector factory are hash-bound.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from role_radar.evaluation.controlled_acquisition.protocols import PLAN_VERSION_V2
from role_radar.evaluation.profile_relevant_acquisition.seed_inputs import SeedInputs

SCHEMA_VERSION: Final[str] = "f10.1f-source-plan-v1"
HEX64_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
NAMESPACE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9\-]+[a-z0-9]$", re.ASCII)
SYNTHETIC_FORBIDDEN_ROOTS: Final[tuple[str, ...]] = (
    "/opt",
    "/etc",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/run",
    "/srv",
)


class SourcePlanError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SourcePlanBudget:
    """Explicit budget identity and bound embedded in an F10.1F plan."""

    budget_id: str
    maximum: int

    def __post_init__(self) -> None:
        if not isinstance(self.budget_id, str) or not self.budget_id.strip():
            raise SourcePlanError("source_plan_budget_invalid")
        if not isinstance(self.maximum, int) or isinstance(self.maximum, bool) or self.maximum < 0:
            raise SourcePlanError("source_plan_budget_invalid")


@dataclass(frozen=True, slots=True)
class SourcePlan:
    """The only source-plan type accepted by the F10.1F Gate D boundary."""

    version: str
    namespace: str
    root: str
    per_board_cap: int
    per_company_cap: int
    budget: SourcePlanBudget
    seed: SeedInputs
    operation_id: str
    lineage_id: str
    source_configs: tuple[Mapping[str, object], ...]
    canonical_bytes: bytes
    source_plan_sha256: str

    @property
    def plan_version(self) -> str:
        """Adapter-facing version required by the ephemeral collector factory."""

        return PLAN_VERSION_V2

    @property
    def sha256(self) -> str:
        """Compatibility spelling for the already-bound canonical digest."""

        return self.source_plan_sha256

    def __post_init__(self) -> None:
        if self.version != SCHEMA_VERSION:
            raise SourcePlanError("source_plan_version_invalid")
        if not isinstance(self.namespace, str) or NAMESPACE_RE.fullmatch(self.namespace) is None:
            raise SourcePlanError("source_plan_namespace_invalid")
        if not isinstance(self.root, str) or not self.root.startswith("/"):
            raise SourcePlanError("source_plan_root_invalid")
        if any(
            self.root == prefix or self.root.startswith(prefix + "/")
            for prefix in SYNTHETIC_FORBIDDEN_ROOTS
        ):
            raise SourcePlanError("source_plan_production_root_rejected")
        for name, value in (
            ("per_board_cap", self.per_board_cap),
            ("per_company_cap", self.per_company_cap),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise SourcePlanError(f"source_plan_{name}_invalid")
        if not isinstance(self.budget, SourcePlanBudget):
            raise SourcePlanError("source_plan_budget_invalid")
        if not isinstance(self.seed, SeedInputs):
            raise SourcePlanError("source_plan_seed_invalid")
        for name, text_value in (("operation", self.operation_id), ("lineage", self.lineage_id)):
            if not isinstance(text_value, str) or not text_value.strip():
                raise SourcePlanError(f"source_plan_{name}_invalid")
        if not isinstance(self.source_configs, tuple) or not self.source_configs:
            raise SourcePlanError("source_plan_sources_invalid")
        if len(self.source_configs) > 30:
            raise SourcePlanError("source_plan_sources_invalid")
        for item in self.source_configs:
            if not isinstance(item, Mapping):
                raise SourcePlanError("source_plan_source_invalid")
            if set(item) != {"family", "source_key", "configuration_version", "configuration"}:
                raise SourcePlanError("source_plan_source_invalid")
            if not isinstance(item["family"], str) or not isinstance(item["source_key"], str):
                raise SourcePlanError("source_plan_source_invalid")
            if item["configuration_version"] != 1 or not isinstance(item["configuration"], Mapping):
                raise SourcePlanError("source_plan_source_invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise SourcePlanError("source_plan_bytes_invalid")
        if HEX64_RE.fullmatch(self.source_plan_sha256) is None:
            raise SourcePlanError("source_plan_hash_invalid")
        expected = self._payload()
        try:
            canonical = _canonical(expected)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise SourcePlanError("source_plan_canonical_invalid") from exc
        if canonical != self.canonical_bytes:
            raise SourcePlanError("source_plan_canonical_mismatch")
        if hashlib.sha256(canonical).hexdigest() != self.source_plan_sha256:
            raise SourcePlanError("source_plan_hash_mismatch")

    def _payload(self) -> dict[str, object]:
        return {
            "budget": {"budget_id": self.budget.budget_id, "maximum": self.budget.maximum},
            "lineage_id": self.lineage_id,
            "namespace": self.namespace,
            "operation_id": self.operation_id,
            "per_board_cap": self.per_board_cap,
            "per_company_cap": self.per_company_cap,
            "root": self.root,
            "schema_version": self.version,
            "seed": {
                "partition_seed": self.seed.partition_seed,
                "selection_seed": self.seed.selection_seed,
            },
            "source_configs": [dict(item) for item in self.source_configs],
        }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def build_source_plan(
    *,
    namespace: str,
    root: str,
    per_board_cap: int,
    per_company_cap: int,
    budget: SourcePlanBudget,
    seed: SeedInputs,
    operation_id: str,
    lineage_id: str,
    source_configs: tuple[Mapping[str, object], ...],
) -> SourcePlan:
    """Build a fully explicit plan; no field has an execution default."""

    payload = {
        "budget": {"budget_id": budget.budget_id, "maximum": budget.maximum},
        "lineage_id": lineage_id,
        "namespace": namespace,
        "operation_id": operation_id,
        "per_board_cap": per_board_cap,
        "per_company_cap": per_company_cap,
        "root": root,
        "schema_version": SCHEMA_VERSION,
        "seed": {
            "partition_seed": seed.partition_seed,
            "selection_seed": seed.selection_seed,
        },
        "source_configs": [dict(item) for item in source_configs],
    }
    canonical = _canonical(payload)
    return SourcePlan(
        version=SCHEMA_VERSION,
        namespace=namespace,
        root=root,
        per_board_cap=per_board_cap,
        per_company_cap=per_company_cap,
        budget=budget,
        seed=seed,
        operation_id=operation_id,
        lineage_id=lineage_id,
        source_configs=source_configs,
        canonical_bytes=canonical,
        source_plan_sha256=hashlib.sha256(canonical).hexdigest(),
    )


# Descriptive alias for callers that need to distinguish this from the
# historical controlled-acquisition model by type name.
F101FSourcePlan = SourcePlan


__all__ = [
    "SCHEMA_VERSION",
    "F101FSourcePlan",
    "SourcePlan",
    "SourcePlanBudget",
    "SourcePlanError",
    "build_source_plan",
]
