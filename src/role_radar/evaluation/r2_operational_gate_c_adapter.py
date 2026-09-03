from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import (
    execute_gate_c_report_only,
)
from role_radar.evaluation.r2_operational_artifacts import R2GateCResolver, R2OfficialProvider
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


def invoke_gate_c(
    packet: OperationPacket,
    capability: ProductionR2Capability,
    resolver: R2GateCResolver,
    provider: R2OfficialProvider,
) -> Mapping[str, object]:
    if packet.gate != "c" or not capability.verify_for(packet):
        raise ValueError("binding_mismatch")
    resolved = resolver.resolve_gate_c(packet, capability)
    if (resolved.operation_id, resolved.lineage_id, resolved.packet_sha256) != (
        packet.operation_id,
        packet.lineage_id,
        packet.packet_sha256,
    ):
        raise ValueError("binding_mismatch")
    if (
        resolved.evidence_root != Path(packet.destination_root)
        or resolved.plan.plan_sha256 != packet.query_plan_sha256
    ):
        raise ValueError("binding_mismatch")
    result = execute_gate_c_report_only(
        authorization=resolved.authorization,
        accepted_b=resolved.accepted_b,
        plan=resolved.plan,
        provider=provider,
        evidence_root=resolved.evidence_root,
    )
    return {
        "evidence_sha256": result.public.report_sha256 or "",
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_gate_c"]
