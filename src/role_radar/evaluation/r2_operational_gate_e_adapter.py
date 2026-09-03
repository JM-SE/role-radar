from __future__ import annotations

from collections.abc import Mapping

from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import authorize_gate_e
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
    if resolved.gate_d_result is not resolved.request.gate_d_result:
        raise ValueError("binding_mismatch")
    authorize_gate_e(resolved.request)
    if (resolved.operation_id, resolved.lineage_id, resolved.source_plan_sha256) != (
        packet.operation_id,
        packet.lineage_id,
        packet.source_plan_sha256,
    ):
        raise ValueError("binding_mismatch")
    request = resolved.request
    if (
        request.operation_id != packet.operation_id
        or request.lineage_id != packet.lineage_id
        or request.current_commit_sha256 != packet.commit_sha256
        or request.gate_d_request.namespace != packet.destination_namespace
        or str(request.gate_d_request.evidence_root) != packet.destination_root
        or request.gate_d_request.seeds.selection_seed != packet.selection_seed_sha256
        or request.gate_d_request.seeds.partition_seed != packet.partition_seed_sha256
        or request.gate_d_request.budget_units != packet.budget
    ):
        raise ValueError("binding_mismatch")
    result = run_gate_e_offline_preview(authorization=resolved.request)
    return {
        "evidence_sha256": result.public.sanitized_preview_sha256 or "",
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_gate_e"]
