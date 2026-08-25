"""Stable error contract for F10.1E profile relevance."""

from __future__ import annotations


class ProfileRelevanceError(ValueError):
    """Base with stable snake-case code; no payload fragments in text."""

    def __init__(self, code: str) -> None:
        self.code: str = code
        super().__init__(code)


class ProfileHashMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "profile_hash_mismatch") -> None:
        super().__init__(code)


class PolicyHashMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "policy_hash_mismatch") -> None:
        super().__init__(code)


class SnapshotNotSealedError(ProfileRelevanceError):
    def __init__(self, code: str = "snapshot_not_sealed") -> None:
        super().__init__(code)


class AcquisitionHashMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "acquisition_hash_mismatch") -> None:
        super().__init__(code)


class SnapshotDuplicateIdentityError(ProfileRelevanceError):
    def __init__(self, code: str = "snapshot_duplicate_identity") -> None:
        super().__init__(code)


class SourceIdentityInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "source_identity_invalid") -> None:
        super().__init__(code)


class InputSchemaInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "input_schema_invalid") -> None:
        super().__init__(code)


class InputLimitExceededError(ProfileRelevanceError):
    def __init__(self, code: str = "input_limit_exceeded") -> None:
        super().__init__(code)


class HistoricalExclusionMissingError(ProfileRelevanceError):
    def __init__(self, code: str = "historical_exclusion_missing") -> None:
        super().__init__(code)


class HistoricalExclusionIncompleteError(ProfileRelevanceError):
    def __init__(self, code: str = "historical_exclusion_incomplete") -> None:
        super().__init__(code)


class HistoricalExclusionStaleError(ProfileRelevanceError):
    def __init__(self, code: str = "historical_exclusion_stale") -> None:
        super().__init__(code)


class HistoricalExclusionHashMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "historical_exclusion_hash_mismatch") -> None:
        super().__init__(code)


class IdentityPolicyMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "identity_policy_mismatch") -> None:
        super().__init__(code)


class FactsBindingMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "facts_binding_mismatch") -> None:
        super().__init__(code)


class GateReasonInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "gate_reason_invalid") -> None:
        super().__init__(code)


class GateOutputIncompleteError(ProfileRelevanceError):
    def __init__(self, code: str = "gate_output_incomplete") -> None:
        super().__init__(code)


class ForbiddenEvidenceFieldError(ProfileRelevanceError):
    def __init__(self, code: str = "forbidden_evidence_field") -> None:
        super().__init__(code)


class QuotaMatrixIncompleteError(ProfileRelevanceError):
    def __init__(self, code: str = "quota_matrix_incomplete") -> None:
        super().__init__(code)


class QuotaCardinalityInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "quota_cardinality_invalid") -> None:
        super().__init__(code)


class SamplingCellInsufficientError(ProfileRelevanceError):
    def __init__(self, code: str = "sampling_cell_insufficient") -> None:
        super().__init__(code)


class BoardCapExceededError(ProfileRelevanceError):
    def __init__(self, code: str = "board_cap_exceeded") -> None:
        super().__init__(code)


class CompanyCapInfeasibleError(ProfileRelevanceError):
    def __init__(self, code: str = "company_cap_infeasible") -> None:
        super().__init__(code)


class SelectionSeedInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "selection_seed_invalid") -> None:
        super().__init__(code)


class SelectionCollisionError(ProfileRelevanceError):
    def __init__(self, code: str = "selection_collision") -> None:
        super().__init__(code)


class HistoricalIdentitySelectedError(ProfileRelevanceError):
    def __init__(self, code: str = "historical_identity_selected") -> None:
        super().__init__(code)


class InclusionProbabilityInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "inclusion_probability_invalid") -> None:
        super().__init__(code)


class PartitionSeedInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "partition_seed_invalid") -> None:
        super().__init__(code)


class PartitionQuotaInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "partition_quota_invalid") -> None:
        super().__init__(code)


class PartitionMembershipInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "partition_membership_invalid") -> None:
        super().__init__(code)


class LiveValuesUnapprovedError(ProfileRelevanceError):
    def __init__(self, code: str = "live_values_unapproved") -> None:
        super().__init__(code)


class OfflineScopeRequiredError(ProfileRelevanceError):
    def __init__(self, code: str = "offline_scope_required") -> None:
        super().__init__(code)


class PreviewBindingMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "preview_binding_mismatch") -> None:
        super().__init__(code)


class ApprovedPreviewRequiredError(ProfileRelevanceError):
    def __init__(self, code: str = "approved_preview_required") -> None:
        super().__init__(code)


class ApprovedPreviewBindingMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "approved_preview_binding_mismatch") -> None:
        super().__init__(code)


class MaterializationContextInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "materialization_context_invalid") -> None:
        super().__init__(code)


class MaterializationContextMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "materialization_context_mismatch") -> None:
        super().__init__(code)


class ApprovalBindingMismatchError(ProfileRelevanceError):
    def __init__(self, code: str = "approval_binding_mismatch") -> None:
        super().__init__(code)


class CrossGateSubstitutionError(ProfileRelevanceError):
    def __init__(self, code: str = "cross_gate_substitution") -> None:
        super().__init__(code)


class PayloadSchemaInvalidError(ProfileRelevanceError):
    def __init__(self, code: str = "payload_schema_invalid") -> None:
        super().__init__(code)


class PayloadFieldForbiddenError(ProfileRelevanceError):
    def __init__(self, code: str = "payload_field_forbidden") -> None:
        super().__init__(code)


class OpaqueIdCollisionError(ProfileRelevanceError):
    def __init__(self, code: str = "opaque_id_collision") -> None:
        super().__init__(code)
