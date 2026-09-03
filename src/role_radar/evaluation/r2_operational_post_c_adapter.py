from __future__ import annotations

from collections.abc import Mapping

from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    validate_post_c_request,
)
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_service import (
    preregister_post_c,
)
from role_radar.evaluation.r2_operational_artifacts import R2PostCResolver, R2PrivateSealWriter
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


def invoke_post_c(
    packet: OperationPacket,
    capability: ProductionR2Capability,
    resolver: R2PostCResolver,
    writer: R2PrivateSealWriter,
) -> Mapping[str, object]:
    if packet.gate != "post-c" or not capability.verify_for(packet):
        raise ValueError("binding_mismatch")
    resolved = resolver.resolve_post_c(packet, capability)
    validate_post_c_request(resolved.request)
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
        or request.authorization.provenance.candidate_commit_sha256 != packet.commit_sha256
        or request.authorization.provenance.query_plan_sha256 != packet.query_plan_sha256
        or request.authorization.provenance.namespace != packet.destination_namespace
        or request.authorization.provenance.approved_root != packet.destination_root
        or request.seeds.selection_seed != packet.selection_seed_sha256
        or request.seeds.partition_seed != packet.partition_seed_sha256
        or request.artifact_class != "offline_private_report_only"
    ):
        raise ValueError("binding_mismatch")
    result = preregister_post_c(request=resolved.request, writer=writer)
    return {
        "evidence_sha256": result.preregistration_sha256,
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_post_c"]
