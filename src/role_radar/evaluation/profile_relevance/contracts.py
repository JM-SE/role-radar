"""Frozen, slotted, deeply immutable DTOs — no parsing, hashing, or I/O."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# --- Primitive DTOs ---


@dataclass(frozen=True, slots=True)
class FrozenProfile:
    profile_id: str
    version: int
    schema_version: str
    payload_canonical_json: str
    content_sha256: str
    binding_sha256: str
    frozen_at_utc: str

    def __post_init__(self) -> None:
        if not self.profile_id or not self.profile_id.strip():
            raise ValueError("profile_id invalid")
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("version invalid")
        if not self.schema_version or not self.schema_version.strip():
            raise ValueError("schema_version invalid")
        if not self.content_sha256 or not self.binding_sha256:
            raise ValueError("hash invalid")
        if not self.frozen_at_utc:
            raise ValueError("frozen_at_utc invalid")


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    source_family: str
    source_id: str
    board_id: str
    board_key: str
    source_snapshot_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "source_family",
            "source_id",
            "board_id",
            "board_key",
            "source_snapshot_sha256",
        ):
            val = getattr(self, name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"{name} invalid")


@dataclass(frozen=True, slots=True)
class AcquisitionObservation:
    observation_id: str
    item_semantic_sha256: str
    strong_identity_digest: str
    identity_policy_version: str
    source: SourceIdentity
    company_sampling_key: str
    title: str
    description: str
    location: str
    remote_evidence: str | None
    employment_evidence: str | None
    authorization_evidence: str | None
    region_evidence: str | None
    canonical_observation_bytes: bytes

    def __post_init__(self) -> None:
        for name in (
            "observation_id",
            "item_semantic_sha256",
            "strong_identity_digest",
            "identity_policy_version",
            "company_sampling_key",
        ):
            val = getattr(self, name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"{name} invalid")
        if not isinstance(self.source, SourceIdentity):
            raise TypeError("source invalid")
        if not isinstance(self.canonical_observation_bytes, bytes):
            raise TypeError("canonical_observation_bytes invalid")


@dataclass(frozen=True, slots=True)
class SealedAcquisitionSnapshot:
    namespace: str
    snapshot_id: str
    schema_version: str
    state: Literal["sealed"]
    acquisition_started_at_utc: str
    sealed_at_utc: str
    acquisition_semantic_sha256: str
    discovery_policy_sha256: str
    source_plan_sha256: str
    observations: tuple[AcquisitionObservation, ...]

    def __post_init__(self) -> None:
        if self.state != "sealed":
            raise ValueError("snapshot_not_sealed")
        for name in (
            "namespace",
            "snapshot_id",
            "schema_version",
            "acquisition_started_at_utc",
            "sealed_at_utc",
            "acquisition_semantic_sha256",
            "discovery_policy_sha256",
            "source_plan_sha256",
        ):
            val = getattr(self, name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"{name} invalid")
        if not isinstance(self.observations, tuple):
            raise TypeError("observations must be tuple")
        # Duplicate checks — fail closed
        seen_obs: set[str] = set()
        seen_sem: set[str] = set()
        seen_strong: set[str] = set()
        for obs in self.observations:
            if not isinstance(obs, AcquisitionObservation):
                raise TypeError("observation invalid")
            if obs.observation_id in seen_obs:
                raise ValueError("snapshot_duplicate_identity")
            if obs.item_semantic_sha256 in seen_sem:
                raise ValueError("snapshot_duplicate_identity")
            if obs.strong_identity_digest in seen_strong:
                raise ValueError("snapshot_duplicate_identity")
            seen_obs.add(obs.observation_id)
            seen_sem.add(obs.item_semantic_sha256)
            seen_strong.add(obs.strong_identity_digest)


@dataclass(frozen=True, slots=True)
class ConstraintPolicy:
    approved_regions: tuple[str, ...] | None = None
    approved_remote: tuple[str, ...] | None = None
    approved_employment: tuple[str, ...] | None = None
    approved_authorizations: tuple[str, ...] | None = None
    evidence_map: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "approved_regions",
            "approved_remote",
            "approved_employment",
            "approved_authorizations",
        ):
            val = getattr(self, name)
            if val is not None and not isinstance(val, tuple):
                raise TypeError(f"{name} must be tuple or None")


@dataclass(frozen=True, slots=True)
class RelevancePolicy:
    policy_id: str
    policy_version: str
    schema_version: str
    profile_binding_sha256: str
    normalization_version: str
    facts_version: str
    gate_version: str
    reason_version: str
    stratum_version: str
    approved_role_aliases: tuple[str, ...]
    core_skills: tuple[str, ...]
    secondary_skills: tuple[str, ...]
    excluded_role_aliases: tuple[str, ...]
    excluded_technologies: tuple[str, ...]
    constraints: ConstraintPolicy
    execution_scope: str
    canonical_bytes: bytes
    policy_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "policy_id",
            "policy_version",
            "schema_version",
            "profile_binding_sha256",
            "policy_sha256",
            "execution_scope",
        ):
            val = getattr(self, name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"{name} invalid")
        if not isinstance(self.constraints, ConstraintPolicy):
            raise TypeError("constraints invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise TypeError("canonical_bytes invalid")


@dataclass(frozen=True, slots=True)
class HistoricalIdentityExclusion:
    exclusion_id: str
    schema_version: str
    policy_version: str
    kind: Literal["complete_inventory_digest_set", "custodian_one_way_denylist"]
    identity_policy_version: str
    scope: Literal["complete"]
    created_at_utc: str
    digests: tuple[str, ...]
    count: int
    exclusion_sha256: str

    def __post_init__(self) -> None:
        if self.kind not in ("complete_inventory_digest_set", "custodian_one_way_denylist"):
            raise ValueError("kind invalid")
        if self.scope != "complete":
            raise ValueError("scope invalid")
        if not isinstance(self.digests, tuple):
            raise TypeError("digests must be tuple")
        if self.count != len(self.digests):
            raise ValueError("count mismatch")
        if tuple(sorted(self.digests)) != self.digests:
            raise ValueError("digests must be sorted")
        if not isinstance(self.exclusion_sha256, str) or not self.exclusion_sha256.strip():
            raise ValueError("exclusion_sha256 invalid")


@dataclass(frozen=True, slots=True)
class QuotaCell:
    source_unit: str
    stratum: str
    corpus_quota: int

    def __post_init__(self) -> None:
        if not isinstance(self.source_unit, str) or not self.source_unit.strip():
            raise ValueError("source_unit invalid")
        if not isinstance(self.stratum, str) or not self.stratum.strip():
            raise ValueError("stratum invalid")
        if not isinstance(self.corpus_quota, int) or self.corpus_quota < 0:
            raise ValueError("corpus_quota invalid")


@dataclass(frozen=True, slots=True)
class SamplingPolicy:
    policy_id: str
    policy_version: str
    schema_version: str
    selection_input_sha256: str
    relevance_policy_sha256: str
    corpus_cardinality: int
    quotas: tuple[QuotaCell, ...]
    per_board_cap: int
    global_per_company_cap: int
    allocation_protocol: str
    selection_seed: str
    selection_rank_domain: str
    rank_protocol: str
    insufficient_inventory_behavior: Literal["fail_closed"]
    execution_scope: str
    canonical_bytes: bytes
    sampling_policy_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.quotas, tuple):
            raise TypeError("quotas must be tuple")
        if self.insufficient_inventory_behavior != "fail_closed":
            raise ValueError("insufficient_inventory_behavior invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise TypeError("canonical_bytes invalid")


@dataclass(frozen=True, slots=True)
class PartitionQuota:
    source_unit: str
    stratum: str
    pilot_quota: int

    def __post_init__(self) -> None:
        if not isinstance(self.source_unit, str) or not self.source_unit.strip():
            raise ValueError("source_unit invalid")
        if not isinstance(self.stratum, str) or not self.stratum.strip():
            raise ValueError("stratum invalid")
        if not isinstance(self.pilot_quota, int) or self.pilot_quota < 0:
            raise ValueError("pilot_quota invalid")


@dataclass(frozen=True, slots=True)
class PartitionPolicy:
    policy_id: str
    policy_version: str
    schema_version: str
    sampling_policy_sha256: str
    pilot_quotas: tuple[PartitionQuota, ...]
    total_count: int
    pilot_count: int
    holdout_count: int
    partition_seed: str
    partition_rank_domain: str
    rank_protocol: str
    execution_scope: str
    canonical_bytes: bytes
    partition_policy_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.pilot_quotas, tuple):
            raise TypeError("pilot_quotas must be tuple")
        if self.holdout_count != self.total_count - self.pilot_count:
            raise ValueError("holdout_count invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise TypeError("canonical_bytes invalid")


@dataclass(frozen=True, slots=True)
class ProfileRelevanceInput:
    frozen_profile: FrozenProfile
    sealed_snapshot: SealedAcquisitionSnapshot
    historical_exclusion: HistoricalIdentityExclusion
    relevance_policy: RelevancePolicy
    sampling_policy: SamplingPolicy
    partition_policy: PartitionPolicy
    input_schema_version: str
    input_version: str
    selection_input_sha256: str
    canonical_aggregate_bytes: bytes
    preview_input_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.frozen_profile, FrozenProfile):
            raise TypeError("frozen_profile invalid")
        if not isinstance(self.sealed_snapshot, SealedAcquisitionSnapshot):
            raise TypeError("sealed_snapshot invalid")
        if not isinstance(self.historical_exclusion, HistoricalIdentityExclusion):
            raise TypeError("historical_exclusion invalid")
        if not isinstance(self.relevance_policy, RelevancePolicy):
            raise TypeError("relevance_policy invalid")
        if not isinstance(self.sampling_policy, SamplingPolicy):
            raise TypeError("sampling_policy invalid")
        if not isinstance(self.partition_policy, PartitionPolicy):
            raise TypeError("partition_policy invalid")
        if not isinstance(self.canonical_aggregate_bytes, bytes):
            raise TypeError("canonical_aggregate_bytes invalid")


@dataclass(frozen=True, slots=True)
class ProjectedFacts:
    item_semantic_sha256: str
    source_unit: str
    company_sampling_key: str
    strong_identity_digest: str
    matched_approved_aliases: tuple[str, ...]
    matched_excluded_aliases: tuple[str, ...]
    supporting_core_matches: tuple[str, ...]
    supporting_secondary_matches: tuple[str, ...]
    excluded_technology_matches: tuple[str, ...]
    constraint_states: tuple[tuple[str, str], ...]
    input_sha256: str
    profile_sha256: str
    policy_sha256: str
    acquisition_sha256: str
    fact_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.item_semantic_sha256, str) or not self.item_semantic_sha256.strip():
            raise ValueError("item_semantic_sha256 invalid")


@dataclass(frozen=True, slots=True)
class GateDecision:
    item_semantic_sha256: str
    stratum: Literal["candidate", "near_miss", "background_control", "indeterminate"]
    reason_codes: tuple[str, ...]
    input_sha256: str
    profile_sha256: str
    policy_sha256: str
    acquisition_sha256: str
    fact_sha256: str
    gate_protocol: str
    decision_sha256: str

    def __post_init__(self) -> None:
        if self.stratum not in ("candidate", "near_miss", "background_control", "indeterminate"):
            raise ValueError("stratum invalid")
        if not isinstance(self.reason_codes, tuple):
            raise TypeError("reason_codes must be tuple")


@dataclass(frozen=True, slots=True)
class SamplingMicrocell:
    source_unit: str
    stratum: str
    company_sampling_key: str
    population_count: int
    allocated_count: int
    remaining_company_capacity: int
    canonical_allocation_tie_key: str
    probability_numerator: int
    probability_denominator: int
    allocation_protocol: str

    def __post_init__(self) -> None:
        if not isinstance(self.population_count, int) or self.population_count < 0:
            raise ValueError("population_count invalid")
        if not isinstance(self.allocated_count, int) or self.allocated_count < 0:
            raise ValueError("allocated_count invalid")
        if self.allocated_count > self.population_count:
            raise ValueError("allocated_count exceeds population")


@dataclass(frozen=True, slots=True)
class SelectedItem:
    decision: GateDecision
    rank_hash: str
    microcell: SamplingMicrocell
    inclusion_probability_numerator: int
    inclusion_probability_denominator: int
    inverse_weight_numerator: int
    inverse_weight_denominator: int

    def __post_init__(self) -> None:
        if not isinstance(self.decision, GateDecision):
            raise TypeError("decision invalid")
        if not isinstance(self.microcell, SamplingMicrocell):
            raise TypeError("microcell invalid")


@dataclass(frozen=True, slots=True)
class SelectionResult:
    excluded: tuple[str, ...]
    eligible: tuple[str, ...]
    selected: tuple[SelectedItem, ...]
    source_stratum_summaries: tuple[tuple[str, str, int], ...]
    microcell_summaries: tuple[SamplingMicrocell, ...]
    corpus_count: int
    selected_count: int
    policy_sha256: str
    input_sha256: str
    selection_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.selected, tuple):
            raise TypeError("selected must be tuple")


@dataclass(frozen=True, slots=True)
class PartitionResult:
    selection_sha256: str
    pilot_item_hashes: tuple[str, ...]
    holdout_item_hashes: tuple[str, ...]
    per_cell_split_counts: tuple[tuple[str, str, int, int], ...]
    pilot_membership_sha256: str
    holdout_membership_sha256: str
    partition_sha256: str

    def __post_init__(self) -> None:
        if set(self.pilot_item_hashes) & set(self.holdout_item_hashes):
            raise ValueError("pilot/holdout overlap")
        if not isinstance(self.pilot_membership_sha256, str) or not isinstance(
            self.holdout_membership_sha256, str
        ):
            raise ValueError("membership hash invalid")


@dataclass(frozen=True, slots=True)
class SanitizedPreview:
    canonical_payload: bytes
    preview_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_payload, bytes):
            raise TypeError("canonical_payload must be bytes")


@dataclass(frozen=True, slots=True)
class PreviewComputationResult:
    facts: tuple[ProjectedFacts, ...]
    decisions: tuple[GateDecision, ...]
    selection: SelectionResult
    partition: PartitionResult
    sanitized_preview: SanitizedPreview
    selection_sha256: str
    partition_sha256: str
    pilot_membership_sha256: str
    holdout_membership_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.facts, tuple) or not isinstance(self.decisions, tuple):
            raise TypeError("facts/decisions must be tuples")


@dataclass(frozen=True, slots=True)
class ApprovedPreview:
    preview_input_sha256: str
    selection_sha256: str
    partition_sha256: str
    pilot_membership_sha256: str
    holdout_membership_sha256: str
    approval_binding_sha256: str
    operation_binding_sha256: str
    lineage_binding_sha256: str
    schema_version: str
    approved_by: str
    approved_at_utc: str

    def __post_init__(self) -> None:
        for name in (
            "preview_input_sha256",
            "selection_sha256",
            "partition_sha256",
            "pilot_membership_sha256",
            "holdout_membership_sha256",
            "approval_binding_sha256",
            "operation_binding_sha256",
            "lineage_binding_sha256",
        ):
            val = getattr(self, name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"{name} invalid")


@dataclass(frozen=True, slots=True)
class MaterializationContext:
    inputs: ProfileRelevanceInput
    display_values: tuple[tuple[str, str], ...]
    provenance_values: tuple[tuple[str, str], ...]
    expected_approved_preview: ApprovedPreview
    operation_binding_sha256: str
    lineage_binding_sha256: str
    schema_version: str
    materialization_domain: str
    materialization_context_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.inputs, ProfileRelevanceInput):
            raise TypeError("inputs invalid")
        if not isinstance(self.expected_approved_preview, ApprovedPreview):
            raise TypeError("expected_approved_preview invalid")


@dataclass(frozen=True, slots=True)
class CanonicalPayload:
    logical_name: str
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.logical_name, str) or not self.logical_name.strip():
            raise ValueError("logical_name invalid")
        if not isinstance(self.canonical_bytes, bytes):
            raise TypeError("canonical_bytes invalid")


@dataclass(frozen=True, slots=True)
class MaterializedPayloads:
    private_payloads: tuple[CanonicalPayload, ...]
    operator_payloads: tuple[CanonicalPayload, ...]
    pilot_payloads: tuple[CanonicalPayload, ...]
    holdout_payloads: tuple[CanonicalPayload, ...]

    def __post_init__(self) -> None:
        for name in ("private_payloads", "operator_payloads", "pilot_payloads", "holdout_payloads"):
            val = getattr(self, name)
            if not isinstance(val, tuple):
                raise TypeError(f"{name} must be tuple")
            for item in val:
                if not isinstance(item, CanonicalPayload):
                    raise TypeError(f"{name} contains invalid payload")
