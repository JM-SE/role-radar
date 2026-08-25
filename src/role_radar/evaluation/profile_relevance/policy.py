"""Versioned schemas, domains, ceilings, vocabularies — no live values."""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Final

# Schemas
SCHEMA_INPUT: Final = "f10.1e-profile-relevance-input-v1"
SCHEMA_SANITIZED_PREVIEW: Final = "f10.1e-profile-relevance-sanitized-preview-v1"
SCHEMA_PREVIEW_COMPUTATION: Final = "f10.1e-profile-relevance-preview-computation-v1"
SCHEMA_APPROVED_PREVIEW: Final = "f10.1e-profile-relevance-approved-preview-v1"
SCHEMA_MATERIALIZATION_CONTEXT: Final = "f10.1e-profile-relevance-materialization-context-v1"
SCHEMA_PRIVATE_PAYLOAD: Final = "f10.1e-profile-relevance-private-payload-v1"
SCHEMA_OPERATOR_PAYLOAD: Final = "f10.1e-profile-relevance-operator-payload-v1"
SCHEMA_PILOT_VIEW: Final = "f10.1e-profile-relevance-pilot-view-v1"
SCHEMA_PILOT_BINDING: Final = "f10.1e-profile-relevance-pilot-binding-v1"
SCHEMA_HOLDOUT_BINDING: Final = "f10.1e-profile-relevance-holdout-binding-v1"

# Protocols
PROTOCOL_FACTS: Final = "f10.1e-facts-v1"
PROTOCOL_GATE: Final = "f10.1e-high-recall-gate-v1"
PROTOCOL_SELECTION: Final = "f10.1e-source-stratum-selection-v1"
PROTOCOL_PARTITION: Final = "f10.1e-source-stratum-partition-v1"
PROTOCOL_MATERIALIZATION: Final = "f10.1e-profile-relevance-materialization-v1"
PROTOCOL_ALLOCATION: Final = "f10.1e-source-stratum-selection-v1"

# Hash domains
DOMAIN_PROFILE_BINDING: Final = "role-radar:f10.1e-profile-relevance:profile-binding:v1"
DOMAIN_POLICY: Final = "role-radar:f10.1e-profile-relevance:policy:v1"
DOMAIN_PARENT_POOL: Final = "role-radar:f10.1e-profile-relevance:parent-pool:v1"
DOMAIN_FACT: Final = "role-radar:f10.1e-profile-relevance:fact:v1"
DOMAIN_GATE_DECISION: Final = "role-radar:f10.1e-profile-relevance:gate-decision:v1"
DOMAIN_GATE_ROOT: Final = "role-radar:f10.1e-profile-relevance:gate-root:v1"
DOMAIN_EXCLUSION: Final = "role-radar:f10.1e-profile-relevance:exclusion:v1"
DOMAIN_SAMPLING_POLICY: Final = "role-radar:f10.1e-profile-relevance:sampling-policy:v1"
DOMAIN_CELL_ORDER: Final = "role-radar:f10.1e-profile-relevance:cell-order:v1"
DOMAIN_COMPANY_ALLOCATION: Final = "role-radar:f10.1e-profile-relevance:company-allocation:v1"
DOMAIN_SELECTION_RANK: Final = "role-radar:f10.1e-profile-relevance:selection-rank:v1"
DOMAIN_SELECTION_ROOT: Final = "role-radar:f10.1e-profile-relevance:selection-root:v1"
DOMAIN_PARTITION_POLICY: Final = "role-radar:f10.1e-profile-relevance:partition-policy:v1"
DOMAIN_PARTITION_RANK: Final = "role-radar:f10.1e-profile-relevance:partition-rank:v1"
DOMAIN_PILOT_MEMBERSHIP: Final = "role-radar:f10.1e-profile-relevance:pilot-membership:v1"
DOMAIN_HOLDOUT_MEMBERSHIP: Final = "role-radar:f10.1e-profile-relevance:holdout-membership:v1"
DOMAIN_PARTITION_ROOT: Final = "role-radar:f10.1e-profile-relevance:partition-root:v1"
DOMAIN_PREVIEW_COMPUTATION: Final = "role-radar:f10.1e-profile-relevance:preview-computation:v1"
DOMAIN_SANITIZED_PREVIEW: Final = "role-radar:f10.1e-profile-relevance:sanitized-preview:v1"
DOMAIN_APPROVED_PREVIEW_BINDING: Final = (
    "role-radar:f10.1e-profile-relevance:approved-preview-binding:v1"
)
DOMAIN_MATERIALIZATION_CONTEXT: Final = (
    "role-radar:f10.1e-profile-relevance:materialization-context:v1"
)
DOMAIN_MATERIALIZATION: Final = "role-radar:f10.1e-profile-relevance:materialization:v1"
DOMAIN_DATASET_ID: Final = "role-radar:f10.1e-profile-relevance:dataset-id:v1"
DOMAIN_OPAQUE_ID: Final = "role-radar:f10.1e-profile-relevance:opaque-id:v1"
DOMAIN_BLIND_ORDER: Final = "role-radar:f10.1e-profile-relevance:blind-order:v1"

# Aliases per spec section 6
selection_rank_domain: Final = DOMAIN_SELECTION_RANK
partition_rank_domain: Final = DOMAIN_PARTITION_RANK

# Execution scope
EXECUTION_SCOPE_SYNTHETIC: Final = "synthetic_gate_a"
EXECUTION_SCOPE_LIVE: Final = "live"
ALLOWED_SCOPES: Final = frozenset({EXECUTION_SCOPE_SYNTHETIC})

# Strata
STRATUM_CANDIDATE: Final = "candidate"
STRATUM_NEAR_MISS: Final = "near_miss"
STRATUM_BACKGROUND_CONTROL: Final = "background_control"
STRATUM_INDETERMINATE: Final = "indeterminate"
STRATA: Final = (
    STRATUM_CANDIDATE,
    STRATUM_NEAR_MISS,
    STRATUM_BACKGROUND_CONTROL,
    STRATUM_INDETERMINATE,
)
STRATA_SET: Final = frozenset(STRATA)

# Reason code families and ordered allowlist prefixes
REASON_FAMILIES: Final = (
    "role_anchor",
    "support_core",
    "support_secondary",
    "conflict_role",
    "conflict_technology",
    "constraint_match",
    "constraint_conflict",
    "indeterminate",
)

REASON_PREFIXES: Final = tuple(f"{fam}:" for fam in REASON_FAMILIES)

# Canonical ordered reason codes — allowlist is prefix-based; concrete codes are
# <family>:<stable_id> where stable_id is policy-owned.
# We expose the prefixes as the ordered vocabulary; full validation checks prefix.
REASON_VOCABULARY_ORDER: Final = REASON_FAMILIES

# Safety ceilings
MAX_OBSERVATIONS: Final = 100_000
MAX_QUOTA_CELLS: Final = 10_000
MAX_CORPUS_CARDINALITY: Final = 100_000
MAX_PILOT_CARDINALITY: Final = 50_000
MAX_HOLDOUT_CARDINALITY: Final = 100_000
MAX_COMPANY_CAP: Final = 10_000
MAX_BOARD_CAP: Final = 100_000
MAX_CANONICAL_BYTES: Final = 10 * 1024 * 1024
MAX_EXCLUSION_DIGESTS: Final = 1_000_000
MAX_PROFILE_BYTES: Final = 1 * 1024 * 1024
MAX_POLICY_BYTES: Final = 1 * 1024 * 1024

# Hex patterns
HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
HEX32_BYTES_RE: Final = re.compile(r"^[0-9a-f]{64}$")  # 32 bytes lowercase-hex
HEX64 = HEX64_RE
OPAQUE_ID_RE: Final = re.compile(r"^[0-9a-f]{24}$")

# Schema allowlists
INPUT_SCHEMAS: Final = frozenset({SCHEMA_INPUT})
PREVIEW_SCHEMAS: Final = frozenset({SCHEMA_SANITIZED_PREVIEW, SCHEMA_PREVIEW_COMPUTATION})
MATERIALIZATION_SCHEMAS: Final = frozenset(
    {SCHEMA_APPROVED_PREVIEW, SCHEMA_MATERIALIZATION_CONTEXT}
)
PAYLOAD_SCHEMAS: Final = frozenset(
    {
        SCHEMA_PRIVATE_PAYLOAD,
        SCHEMA_OPERATOR_PAYLOAD,
        SCHEMA_PILOT_VIEW,
        SCHEMA_PILOT_BINDING,
        SCHEMA_HOLDOUT_BINDING,
    }
)

ALL_SCHEMAS: Final = frozenset(
    {
        SCHEMA_INPUT,
        SCHEMA_SANITIZED_PREVIEW,
        SCHEMA_PREVIEW_COMPUTATION,
        SCHEMA_APPROVED_PREVIEW,
        SCHEMA_MATERIALIZATION_CONTEXT,
        SCHEMA_PRIVATE_PAYLOAD,
        SCHEMA_OPERATOR_PAYLOAD,
        SCHEMA_PILOT_VIEW,
        SCHEMA_PILOT_BINDING,
        SCHEMA_HOLDOUT_BINDING,
    }
)

ALL_PROTOCOLS: Final = frozenset(
    {
        PROTOCOL_FACTS,
        PROTOCOL_GATE,
        PROTOCOL_SELECTION,
        PROTOCOL_PARTITION,
        PROTOCOL_MATERIALIZATION,
        PROTOCOL_ALLOCATION,
    }
)

ALL_DOMAINS: Final = frozenset(
    {
        DOMAIN_PROFILE_BINDING,
        DOMAIN_POLICY,
        DOMAIN_PARENT_POOL,
        DOMAIN_FACT,
        DOMAIN_GATE_DECISION,
        DOMAIN_GATE_ROOT,
        DOMAIN_EXCLUSION,
        DOMAIN_SAMPLING_POLICY,
        DOMAIN_CELL_ORDER,
        DOMAIN_COMPANY_ALLOCATION,
        DOMAIN_SELECTION_RANK,
        DOMAIN_SELECTION_ROOT,
        DOMAIN_PARTITION_POLICY,
        DOMAIN_PARTITION_RANK,
        DOMAIN_PILOT_MEMBERSHIP,
        DOMAIN_HOLDOUT_MEMBERSHIP,
        DOMAIN_PARTITION_ROOT,
        DOMAIN_PREVIEW_COMPUTATION,
        DOMAIN_SANITIZED_PREVIEW,
        DOMAIN_APPROVED_PREVIEW_BINDING,
        DOMAIN_MATERIALIZATION_CONTEXT,
        DOMAIN_MATERIALIZATION,
        DOMAIN_DATASET_ID,
        DOMAIN_OPAQUE_ID,
        DOMAIN_BLIND_ORDER,
    }
)

# Logical payload names allowlists
PRIVATE_PAYLOAD_NAMES: Final = frozenset(
    {"preview", "population", "gate_decisions", "sampling_cells", "selection", "provenance"}
)
OPERATOR_PAYLOAD_NAMES: Final = frozenset({"operator_preview"})
PILOT_PAYLOAD_NAMES: Final = frozenset({"pilot_label_view", "pilot_binding"})
HOLDOUT_PAYLOAD_NAMES: Final = frozenset({"holdout_sealed_view", "holdout_binding"})

PILOT_VIEW_ALLOWED_FIELDS: Final = frozenset(
    {"opaque_id", "title", "company", "location", "description"}
)
PILOT_BINDING_ALLOWED_FIELDS: Final = frozenset(
    {"schema", "dataset_id", "split", "count", "pilot_membership_sha256"}
)
HOLDOUT_BINDING_ALLOWED_FIELDS: Final = frozenset(
    {"schema", "dataset_id", "split", "count", "holdout_membership_sha256"}
)

# Forbidden fields in pilot/operator payloads (recursive)
FORBIDDEN_PILOT_FIELDS: Final = frozenset(
    {
        "source",
        "board",
        "stratum",
        "reason",
        "rank",
        "score",
        "probability",
        "weight",
        "identity",
        "sampling",
        "holdout",
        "acquisition_id",
        "strong_identity_digest",
        "item_semantic_sha256",
        "company_sampling_key",
    }
)


def validate_hex32_seed(value: str) -> None:
    """Validate 32-byte lowercase-hex seed; no defaults, no generation."""
    from role_radar.evaluation.profile_relevance.errors import (
        PartitionSeedInvalidError,
        SelectionSeedInvalidError,
    )

    # Generic check; caller decides which error subclass to raise.
    # This helper raises SelectionSeedInvalid by default.
    if not isinstance(value, str) or HEX32_BYTES_RE.fullmatch(value) is None:
        raise SelectionSeedInvalidError("selection_seed_invalid")
    # Also ensure not equal to partition seed pattern? Caller validates distinctness.
    _ = PartitionSeedInvalidError  # keep import used


def validate_execution_scope(value: str) -> None:
    from role_radar.evaluation.profile_relevance.errors import OfflineScopeRequiredError

    if value != EXECUTION_SCOPE_SYNTHETIC:
        raise OfflineScopeRequiredError("offline_scope_required")


def validate_stratum(value: str) -> None:
    from role_radar.evaluation.profile_relevance.errors import GateReasonInvalidError

    if value not in STRATA_SET:
        raise GateReasonInvalidError("gate_reason_invalid")


def validate_reason_code(value: str) -> None:
    from role_radar.evaluation.profile_relevance.errors import GateReasonInvalidError

    if not isinstance(value, str):
        raise GateReasonInvalidError("gate_reason_invalid")
    if ":" not in value:
        raise GateReasonInvalidError("gate_reason_invalid")
    prefix, suffix = value.split(":", 1)
    if f"{prefix}:" not in REASON_PREFIXES:
        raise GateReasonInvalidError("gate_reason_invalid")
    if not suffix or not suffix.strip():
        raise GateReasonInvalidError("gate_reason_invalid")
    # suffix must be stable id, no free text leakage - allow alphanum _ - .
    if not re.fullmatch(r"[a-z0-9_\-\.]+", suffix):
        raise GateReasonInvalidError("gate_reason_invalid")


def validate_reason_sequence(reasons: tuple[str, ...]) -> None:
    from role_radar.evaluation.profile_relevance.errors import GateReasonInvalidError

    if not isinstance(reasons, tuple):
        raise GateReasonInvalidError("gate_reason_invalid")
    seen: set[str] = set()
    last_family_index = -1
    family_order = {fam: idx for idx, fam in enumerate(REASON_FAMILIES)}
    for r in reasons:
        validate_reason_code(r)
        if r in seen:
            raise GateReasonInvalidError("gate_reason_invalid")
        seen.add(r)
        fam = r.split(":", 1)[0]
        idx = family_order[fam]
        # Enforce non-decreasing family order for stability
        if idx < last_family_index:
            raise GateReasonInvalidError("gate_reason_invalid")
        last_family_index = idx


def validate_schema(value: str, allowed: frozenset[str]) -> None:
    from role_radar.evaluation.profile_relevance.errors import InputSchemaInvalidError

    if value not in allowed:
        raise InputSchemaInvalidError("input_schema_invalid")


def validate_hash_hex64(value: str, code: str = "policy_hash_mismatch") -> None:
    from role_radar.evaluation.profile_relevance.errors import ProfileRelevanceError

    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise ProfileRelevanceError(code)


HASH_DOMAINS: Final = MappingProxyType({k: k for k in ALL_DOMAINS})

__all__ = [
    n for n in globals() if n.isupper() or n in ("selection_rank_domain", "partition_rank_domain")
] + [
    "validate_execution_scope",
    "validate_hash_hex64",
    "validate_hex32_seed",
    "validate_reason_code",
    "validate_reason_sequence",
    "validate_schema",
    "validate_stratum",
]
