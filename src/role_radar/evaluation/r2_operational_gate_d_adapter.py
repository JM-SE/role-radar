from __future__ import annotations

import asyncio
from collections.abc import Mapping

from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import authorize_gate_d
from role_radar.evaluation.profile_relevant_acquisition.gate_d_service import (
    execute_gate_d_bounded_acquisition,
)
from role_radar.evaluation.r2_operational_artifacts import R2GateDOfflineFactory, R2GateDResolver
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


def invoke_gate_d(
    packet: OperationPacket,
    capability: ProductionR2Capability,
    resolver: R2GateDResolver,
    factory: R2GateDOfflineFactory,
) -> Mapping[str, object]:
    if packet.gate != "d" or not capability.verify_for(packet):
        raise ValueError("binding_mismatch")
    resolved = resolver.resolve_gate_d(packet, capability)
    request = resolved.request
    if (
        resolved.source_plan is not request.post_c_request.source_plan
        or resolved.post_c_seal is not request.post_c_seal
        or resolved.seeds != request.seeds
        or resolved.window_start_utc != request.window_start_utc
        or resolved.window_end_utc != request.window_end_utc
        or resolved.cutoff_utc != request.cutoff_utc
        or resolved.source_cap != request.per_board_cap
        or resolved.source_cap != request.per_company_cap
        or resolved.budget != request.budget_units
    ):
        raise ValueError("binding_mismatch")
    authorize_gate_d(request)
    if (resolved.operation_id, resolved.lineage_id, request.operation_id, request.lineage_id) != (
        packet.operation_id,
        packet.lineage_id,
        packet.operation_id,
        packet.lineage_id,
    ):
        raise ValueError("binding_mismatch")
    if (
        resolved.source_plan.source_plan_sha256 != packet.source_plan_sha256
        or resolved.source_cap != packet.source_cap
        or resolved.budget != packet.budget
        or resolved.quota != packet.quota
        or resolved.cardinality != packet.cardinality
    ):
        raise ValueError("binding_mismatch")
    if (
        resolved.seeds.selection_seed != packet.selection_seed_sha256
        or resolved.seeds.partition_seed != packet.partition_seed_sha256
        or request.namespace != packet.destination_namespace
        or str(request.evidence_root) != packet.destination_root
        or request.per_board_cap != packet.source_cap
        or request.budget_units != packet.budget
        or request.per_company_cap != packet.source_cap
        or request.current_commit_sha256 != packet.commit_sha256
        or request.artifact_class != "offline_private_report_only"
        or resolved.window_start_utc != packet.window_start.isoformat().replace("+00:00", "Z")
        or resolved.window_end_utc != packet.window_cutoff.isoformat().replace("+00:00", "Z")
        or any(value < 0 for value in request.quotas.values())
        or any(value < 0 for value in request.cardinality.values())
    ):
        raise ValueError("binding_mismatch")
    effects = factory.create(request)
    if effects.test_only_adapter is not request.test_only_adapter:
        raise ValueError("binding_mismatch")
    result = asyncio.run(
        execute_gate_d_bounded_acquisition(
            request=request,
            delegate=effects.delegate,
            collector_factory=effects.collector_factory,
            journal=effects.journal,
            checkpoints=effects.checkpoints or None,
        )
    )
    return {
        "evidence_sha256": result.public.manifest_sha256,
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_gate_d"]
