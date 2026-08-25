"""Pure preview orchestration — validates, projects, gates, selects, partitions, sanitizes."""

from __future__ import annotations

from role_radar.evaluation.profile_relevance.contracts import (
    GateDecision,
    PreviewComputationResult,
    ProfileRelevanceInput,
    ProjectedFacts,
    SanitizedPreview,
)
from role_radar.evaluation.profile_relevance.errors import (
    AcquisitionHashMismatchError,
    FactsBindingMismatchError,
    GateOutputIncompleteError,
    HistoricalExclusionHashMismatchError,
    InputLimitExceededError,
    InputSchemaInvalidError,
    OfflineScopeRequiredError,
    PartitionSeedInvalidError,
    PolicyHashMismatchError,
    PreviewBindingMismatchError,
    ProfileHashMismatchError,
    ProfileRelevanceError,
    SelectionSeedInvalidError,
    SnapshotDuplicateIdentityError,
)
from role_radar.evaluation.profile_relevance.facts import project_facts
from role_radar.evaluation.profile_relevance.gate import decide_gate
from role_radar.evaluation.profile_relevance.hashing import (
    canonical_json_bytes,
    domain_hash,
    domain_hash_bytes,
)
from role_radar.evaluation.profile_relevance.partition import run_partition
from role_radar.evaluation.profile_relevance.policy import (
    DOMAIN_PARTITION_POLICY,
    DOMAIN_PARTITION_RANK,
    DOMAIN_POLICY,
    DOMAIN_PREVIEW_COMPUTATION,
    DOMAIN_SAMPLING_POLICY,
    DOMAIN_SANITIZED_PREVIEW,
    DOMAIN_SELECTION_RANK,
    EXECUTION_SCOPE_SYNTHETIC,
    HEX32_BYTES_RE,
    HEX64_RE,
    MAX_CANONICAL_BYTES,
    MAX_CORPUS_CARDINALITY,
    MAX_EXCLUSION_DIGESTS,
    MAX_HOLDOUT_CARDINALITY,
    MAX_OBSERVATIONS,
    MAX_PILOT_CARDINALITY,
    MAX_QUOTA_CELLS,
    SCHEMA_INPUT,
    SCHEMA_SANITIZED_PREVIEW,
)
from role_radar.evaluation.profile_relevance.selection import run_selection


def _require_hex64(value: str, code: str) -> None:
    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise ProfileRelevanceError(code)


def _require_hex32(value: str, *, is_selection: bool) -> None:
    if not isinstance(value, str) or HEX32_BYTES_RE.fullmatch(value) is None:
        if is_selection:
            raise SelectionSeedInvalidError("selection_seed_invalid")
        raise PartitionSeedInvalidError("partition_seed_invalid")


def compute_preview(inputs: ProfileRelevanceInput) -> PreviewComputationResult:
    """Validate scope, bindings, then facts->gate->selection->partition->sanitized preview."""
    if not isinstance(inputs, ProfileRelevanceInput):
        raise PreviewBindingMismatchError("preview_binding_mismatch")

    # Execution scope synthetic only
    for pol in (inputs.relevance_policy, inputs.sampling_policy, inputs.partition_policy):
        if pol.execution_scope != EXECUTION_SCOPE_SYNTHETIC:
            raise OfflineScopeRequiredError("offline_scope_required")

    # Schema allowlist
    if inputs.input_schema_version != SCHEMA_INPUT:
        raise InputSchemaInvalidError("input_schema_invalid")

    # Safety ceilings
    if len(inputs.sealed_snapshot.observations) > MAX_OBSERVATIONS:
        raise InputLimitExceededError("input_limit_exceeded")
    if len(inputs.canonical_aggregate_bytes) > MAX_CANONICAL_BYTES:
        raise InputLimitExceededError("input_limit_exceeded")
    if len(inputs.historical_exclusion.digests) > MAX_EXCLUSION_DIGESTS:
        raise InputLimitExceededError("input_limit_exceeded")
    if len(inputs.sampling_policy.quotas) > MAX_QUOTA_CELLS:
        raise InputLimitExceededError("input_limit_exceeded")
    if inputs.sampling_policy.corpus_cardinality > MAX_CORPUS_CARDINALITY:
        raise InputLimitExceededError("input_limit_exceeded")
    if inputs.partition_policy.total_count > MAX_HOLDOUT_CARDINALITY + MAX_PILOT_CARDINALITY:
        raise InputLimitExceededError("input_limit_exceeded")
    if inputs.partition_policy.pilot_count > MAX_PILOT_CARDINALITY:
        raise InputLimitExceededError("input_limit_exceeded")
    if inputs.partition_policy.holdout_count > MAX_HOLDOUT_CARDINALITY:
        raise InputLimitExceededError("input_limit_exceeded")

    # Hash shape validation
    _require_hex64(inputs.frozen_profile.content_sha256, "profile_hash_mismatch")
    _require_hex64(inputs.frozen_profile.binding_sha256, "profile_hash_mismatch")
    _require_hex64(inputs.relevance_policy.profile_binding_sha256, "profile_hash_mismatch")
    _require_hex64(inputs.relevance_policy.policy_sha256, "policy_hash_mismatch")
    _require_hex64(inputs.sampling_policy.selection_input_sha256, "preview_binding_mismatch")
    _require_hex64(inputs.sampling_policy.relevance_policy_sha256, "policy_hash_mismatch")
    _require_hex64(inputs.sampling_policy.sampling_policy_sha256, "policy_hash_mismatch")
    _require_hex64(inputs.partition_policy.sampling_policy_sha256, "policy_hash_mismatch")
    _require_hex64(inputs.partition_policy.partition_policy_sha256, "policy_hash_mismatch")
    _require_hex64(inputs.selection_input_sha256, "preview_binding_mismatch")
    _require_hex64(inputs.preview_input_sha256, "preview_binding_mismatch")
    _require_hex64(inputs.sealed_snapshot.acquisition_semantic_sha256, "acquisition_hash_mismatch")
    _require_hex64(inputs.sealed_snapshot.discovery_policy_sha256, "policy_hash_mismatch")
    _require_hex64(inputs.sealed_snapshot.source_plan_sha256, "policy_hash_mismatch")
    _require_hex64(
        inputs.historical_exclusion.exclusion_sha256, "historical_exclusion_hash_mismatch"
    )

    # Binding reconciliation
    if inputs.relevance_policy.profile_binding_sha256 != inputs.frozen_profile.binding_sha256:
        raise ProfileHashMismatchError("profile_hash_mismatch")

    # Policy hash back-check via domain hashing over canonical bytes
    if (
        domain_hash_bytes(DOMAIN_POLICY, inputs.relevance_policy.canonical_bytes)
        != inputs.relevance_policy.policy_sha256
    ):
        raise PolicyHashMismatchError("policy_hash_mismatch")
    if (
        domain_hash_bytes(DOMAIN_SAMPLING_POLICY, inputs.sampling_policy.canonical_bytes)
        != inputs.sampling_policy.sampling_policy_sha256
    ):
        raise PolicyHashMismatchError("policy_hash_mismatch")
    if (
        domain_hash_bytes(DOMAIN_PARTITION_POLICY, inputs.partition_policy.canonical_bytes)
        != inputs.partition_policy.partition_policy_sha256
    ):
        raise PolicyHashMismatchError("policy_hash_mismatch")

    if inputs.sampling_policy.relevance_policy_sha256 != inputs.relevance_policy.policy_sha256:
        raise PolicyHashMismatchError("policy_hash_mismatch")
    if inputs.sampling_policy.selection_input_sha256 != inputs.selection_input_sha256:
        raise PreviewBindingMismatchError("preview_binding_mismatch")
    if (
        inputs.partition_policy.sampling_policy_sha256
        != inputs.sampling_policy.sampling_policy_sha256
    ):
        raise PolicyHashMismatchError("policy_hash_mismatch")
    if (
        domain_hash_bytes(DOMAIN_PREVIEW_COMPUTATION, inputs.canonical_aggregate_bytes)
        != inputs.preview_input_sha256
    ):
        raise PreviewBindingMismatchError("preview_binding_mismatch")

    # Seed validation and distinctness
    _require_hex32(inputs.sampling_policy.selection_seed, is_selection=True)
    _require_hex32(inputs.partition_policy.partition_seed, is_selection=False)
    if inputs.sampling_policy.selection_seed == inputs.partition_policy.partition_seed:
        raise PartitionSeedInvalidError("partition_seed_invalid")
    if inputs.sampling_policy.selection_rank_domain != DOMAIN_SELECTION_RANK:
        raise SelectionSeedInvalidError("selection_seed_invalid")
    if inputs.partition_policy.partition_rank_domain != DOMAIN_PARTITION_RANK:
        raise PartitionSeedInvalidError("partition_seed_invalid")

    # Snapshot state already enforced by contract, but double-check
    if inputs.sealed_snapshot.state != "sealed":
        raise AcquisitionHashMismatchError("snapshot_not_sealed")
    # Duplicate already checked in contract; mirror with explicit error
    # (kept for stable code path)
    seen_obs: set[str] = set()
    seen_sem: set[str] = set()
    seen_strong: set[str] = set()
    for obs in inputs.sealed_snapshot.observations:
        if (
            obs.observation_id in seen_obs
            or obs.item_semantic_sha256 in seen_sem
            or obs.strong_identity_digest in seen_strong
        ):
            raise SnapshotDuplicateIdentityError("snapshot_duplicate_identity")
        seen_obs.add(obs.observation_id)
        seen_sem.add(obs.item_semantic_sha256)
        seen_strong.add(obs.strong_identity_digest)
        _require_hex64(obs.item_semantic_sha256, "acquisition_hash_mismatch")
        _require_hex64(obs.strong_identity_digest, "historical_exclusion_hash_mismatch")

    # Facts projection
    facts_list: list[ProjectedFacts] = []
    for obs in inputs.sealed_snapshot.observations:
        fact = project_facts(
            obs,
            inputs.relevance_policy,
            input_sha256=inputs.preview_input_sha256,
            profile_sha256=inputs.frozen_profile.binding_sha256,
            acquisition_sha256=inputs.sealed_snapshot.acquisition_semantic_sha256,
        )
        # Facts binding mismatch guard
        if (
            fact.input_sha256 != inputs.preview_input_sha256
            or fact.profile_sha256 != inputs.frozen_profile.binding_sha256
            or fact.policy_sha256 != inputs.relevance_policy.policy_sha256
            or fact.acquisition_sha256 != inputs.sealed_snapshot.acquisition_semantic_sha256
        ):
            raise FactsBindingMismatchError("facts_binding_mismatch")
        facts_list.append(fact)
    facts_tuple: tuple[ProjectedFacts, ...] = tuple(facts_list)

    # Gate truth table
    decisions_list: list[GateDecision] = []
    for fact in facts_tuple:
        dec = decide_gate(fact)
        decisions_list.append(dec)
    decisions_tuple: tuple[GateDecision, ...] = tuple(decisions_list)

    if len(decisions_tuple) != len(inputs.sealed_snapshot.observations):
        raise GateOutputIncompleteError("gate_output_incomplete")

    # Selection with historical exclusion (separate seed already validated)
    selection = run_selection(
        decisions=decisions_tuple,
        observations=inputs.sealed_snapshot.observations,
        facts=facts_tuple,
        sampling_policy=inputs.sampling_policy,
        historical_exclusion=inputs.historical_exclusion,
        acquisition_started_at_utc=inputs.sealed_snapshot.acquisition_started_at_utc,
    )

    # Partition with separate seed
    semantic_to_strong: dict[str, str] = {
        obs.item_semantic_sha256: obs.strong_identity_digest
        for obs in inputs.sealed_snapshot.observations
    }
    partition = run_partition(
        selection=selection,
        partition_policy=inputs.partition_policy,
        semantic_to_strong=semantic_to_strong,
        observations=inputs.sealed_snapshot.observations,
    )

    # Ensure selection/partition seeds distinct (already) and that hashes are hex
    _require_hex64(selection.selection_sha256, "preview_binding_mismatch")
    _require_hex64(partition.partition_sha256, "preview_binding_mismatch")
    _require_hex64(partition.pilot_membership_sha256, "preview_binding_mismatch")
    _require_hex64(partition.holdout_membership_sha256, "preview_binding_mismatch")

    # Assemble sanitized aggregate preview (no item ids, ranks, probabilities, splits beyond aggregates)
    sanitized_payload: dict[str, object] = {
        "corpus_count": selection.corpus_count,
        "holdout_count": inputs.partition_policy.holdout_count,
        "holdout_membership_sha256": partition.holdout_membership_sha256,
        "partition_sha256": partition.partition_sha256,
        "pilot_count": inputs.partition_policy.pilot_count,
        "pilot_membership_sha256": partition.pilot_membership_sha256,
        "preview_input_sha256": inputs.preview_input_sha256,
        "schema_version": SCHEMA_SANITIZED_PREVIEW,
        "selection_sha256": selection.selection_sha256,
        "total_count": inputs.partition_policy.total_count,
    }
    canonical_without_lf = canonical_json_bytes(sanitized_payload)
    # Logical JSON payload has exactly one trailing LF
    canonical_with_lf = canonical_without_lf + b"\n"
    preview_sha256 = domain_hash(DOMAIN_SANITIZED_PREVIEW, sanitized_payload)
    # Alternate verification via bytes domain hash must match
    preview_sha256_bytes = domain_hash_bytes(DOMAIN_SANITIZED_PREVIEW, canonical_without_lf)
    if preview_sha256 != preview_sha256_bytes:
        raise PreviewBindingMismatchError("preview_binding_mismatch")

    sanitized_preview = SanitizedPreview(
        canonical_payload=canonical_with_lf,
        preview_sha256=preview_sha256,
    )

    # Historical exclusion stale check already done in selection, but explicit hash shape guard
    if (
        not isinstance(inputs.historical_exclusion.exclusion_sha256, str)
        or not inputs.historical_exclusion.exclusion_sha256
    ):
        raise HistoricalExclusionHashMismatchError("historical_exclusion_hash_mismatch")

    return PreviewComputationResult(
        facts=facts_tuple,
        decisions=decisions_tuple,
        selection=selection,
        partition=partition,
        sanitized_preview=sanitized_preview,
        selection_sha256=selection.selection_sha256,
        partition_sha256=partition.partition_sha256,
        pilot_membership_sha256=partition.pilot_membership_sha256,
        holdout_membership_sha256=partition.holdout_membership_sha256,
    )
