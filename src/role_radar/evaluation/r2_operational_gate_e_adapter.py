from __future__ import annotations

from collections.abc import Mapping

from role_radar.evaluation.profile_relevant_acquisition.gate_e_service import (
    run_gate_e_offline_preview,
)
from role_radar.evaluation.r2_operational_artifacts import R2GateEResolver
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


def invoke_gate_e(
    packet: OperationPacket, capability: ProductionR2Capability, resolver: R2GateEResolver
) -> Mapping[str, object]:
    if packet.gate != "e" or not capability.verify_for(packet):
        raise ValueError("binding_mismatch")
    resolved = resolver.resolve_gate_e(packet, capability)
    if (resolved.operation_id, resolved.lineage_id, resolved.source_plan_sha256) != (
        packet.operation_id,
        packet.lineage_id,
        packet.source_plan_sha256,
    ):
        raise ValueError("binding_mismatch")
    result = run_gate_e_offline_preview(authorization=resolved.request)
    return {
        "evidence_sha256": result.public.sanitized_preview_sha256 or "",
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_gate_e"]
