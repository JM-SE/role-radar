"""Pure compatibility assessment for recovered Gate E input."""

from __future__ import annotations

from dataclasses import dataclass

from .recovered_gate_e_preflight_loader import RecoveredGateEProvenance


@dataclass(frozen=True, slots=True)
class RecoveredGateECompatibilityVerdict:
    result: str
    effect: str
    downstream: str
    reason: str
    source_count: int
    parent_pool_count: int
    manifest_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "result": self.result,
            "effect": self.effect,
            "downstream": self.downstream,
            "reason": self.reason,
            "source_count": self.source_count,
            "parent_pool_count": self.parent_pool_count,
            "manifest_sha256": self.manifest_sha256,
        }


def assess_recovered_gate_e_compatibility(
    provenance: RecoveredGateEProvenance,
) -> RecoveredGateECompatibilityVerdict:
    if provenance.synthetic_mode != "bounded":
        raise ValueError("gate_e_preflight_mode_invalid")
    if provenance.parent_pool_count == 0:
        reason = "blocked_no_candidates"
    else:
        reason = "blocked_synthetic_input"
    return RecoveredGateECompatibilityVerdict(
        result=reason,
        effect="disabled",
        downstream="disabled",
        reason=reason,
        source_count=provenance.source_count,
        parent_pool_count=provenance.parent_pool_count,
        manifest_sha256=provenance.manifest_sha256,
    )


__all__ = [
    "RecoveredGateECompatibilityVerdict",
    "assess_recovered_gate_e_compatibility",
]
