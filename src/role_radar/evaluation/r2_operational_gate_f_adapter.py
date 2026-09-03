from __future__ import annotations

from collections.abc import Mapping

from role_radar.evaluation.profile_relevant_acquisition.gate_f_authorization import (
    freeze_bindings_for_request,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_service import (
    run_gate_f_materialization_freeze,
)
from role_radar.evaluation.r2_operational_artifacts import (
    R2Freezer,
    R2GateFResolver,
    R2Materializer,
)
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


def invoke_gate_f(
    packet: OperationPacket,
    capability: ProductionR2Capability,
    resolver: R2GateFResolver,
    materializer: R2Materializer,
    freezer: R2Freezer,
) -> Mapping[str, object]:
    if packet.gate != "f" or not capability.verify_for(packet):
        raise ValueError("binding_mismatch")
    resolved = resolver.resolve_gate_f(packet, capability)
    if (
        resolved.operation_id,
        resolved.lineage_id,
        resolved.source_plan_sha256,
        resolved.destination_root,
    ) != (
        packet.operation_id,
        packet.lineage_id,
        packet.source_plan_sha256,
        resolved.request.destination_root,
    ):
        raise ValueError("binding_mismatch")
    result = run_gate_f_materialization_freeze(
        request=resolved.request,
        freeze_bindings=freeze_bindings_for_request(resolved.request),
        materializer=materializer,
        freezer=freezer,
    )
    return {
        "evidence_sha256": result.public.receipt_sha256,
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_gate_f"]
