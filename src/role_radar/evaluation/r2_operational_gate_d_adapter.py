from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import cast

from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    SyntheticCollectorFactory,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ExternalApprovalBinding,
    ExternalApprovalVerifier,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import authorize_gate_d
from role_radar.evaluation.profile_relevant_acquisition.gate_d_service import (
    execute_gate_d_bounded_acquisition,
)
from role_radar.evaluation.r2_greenhouse_lever_capability import R2GreenhouseLeverCapability
from role_radar.evaluation.r2_operational_artifacts import (
    GateDOfflineEffects,
    GateDOperationalEffects,
    R2GateDOfflineFactory,
    R2GateDOperationalFactory,
    R2GateDResolver,
)
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


def invoke_gate_d(
    packet: OperationPacket,
    capability: ProductionR2Capability,
    resolver: R2GateDResolver,
    factory: R2GateDOfflineFactory | R2GateDOperationalFactory,
    operational_approval: ExternalApprovalBinding | None = None,
    operational_approval_verifier: ExternalApprovalVerifier | None = None,
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
    authorize_gate_d(request, allow_operational=request.test_only_adapter is None)
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
    if request.test_only_adapter is None:
        from role_radar.evaluation.r2_greenhouse_lever_factory import (
            R2GreenhouseLeverCollectorFactory,
            R2GreenhouseLeverFactory,
        )

        concrete_factory = cast(R2GreenhouseLeverFactory, factory)
        if type(concrete_factory) is not R2GreenhouseLeverFactory:
            raise ValueError("r2_operational_factory_required")
        sealed_capability = resolved.operational_capability
        if (
            type(sealed_capability) is not R2GreenhouseLeverCapability
            or sealed_capability.production is not capability
            or concrete_factory.capability is not sealed_capability
            or sealed_capability.claims is not concrete_factory.capability.claims
            or not isinstance(operational_approval, ExternalApprovalBinding)
            or operational_approval_verifier is None
        ):
            raise ValueError("binding_mismatch")
        claims = sealed_capability.claims
        if (
            claims.provider_families != ("greenhouse", "lever")
            or claims.source_plan_sha256 != packet.source_plan_sha256
            or claims.operation_id != packet.operation_id
            or claims.lineage_id != request.lineage_id
            or claims.namespace != packet.destination_namespace
            or claims.root != packet.destination_root
            or claims.window_start != packet.window_start
            or claims.window_cutoff != packet.window_cutoff
            or claims.expires_at != packet.expires_at
            or claims.budget != request.budget_units
            or claims.per_board_cap != request.per_board_cap
            or claims.per_company_cap != request.per_company_cap
            or tuple(dict(item) for item in claims.source_configs)
            != tuple(dict(item) for item in request.post_c_request.source_plan.source_configs)
            or not claims.allowed_hosts
        ):
            raise ValueError("binding_mismatch")
        effects = concrete_factory.create_effects(
            request,
            approval=operational_approval,
            approval_verifier=operational_approval_verifier,
        )
    else:
        effects = factory.create(request)
    delegate: object
    collector_factory: object
    if type(effects) is GateDOfflineEffects:
        if effects.test_only_adapter is not request.test_only_adapter:
            raise ValueError("binding_mismatch")
        delegate = effects.delegate
        collector_factory = effects.collector_factory
        journal = effects.journal
        checkpoints = effects.checkpoints or None
        approval = None
        approval_verifier = None
    elif type(effects) is GateDOperationalEffects:
        # Reject provider-shaped injection before invoking the sealed collector
        # factory or using its transport.
        from role_radar.evaluation.r2_greenhouse_lever_factory import (
            R2GreenhouseLeverFactory,
        )

        if type(effects.factory) is not R2GreenhouseLeverFactory:
            raise ValueError("binding_mismatch")
        if (
            effects.factory.packet is not packet
            or effects.factory.plan is not resolved.source_plan
            or cast(object, effects.delegate) is not cast(object, effects.factory.transport)
            or effects.capability is not resolved.operational_capability
        ):
            raise ValueError("binding_mismatch")

        delegate = cast(object, effects.delegate)
        collector_factory = R2GreenhouseLeverCollectorFactory(effects.factory)
        journal = effects.journal
        checkpoints = effects.checkpoints or None
        approval = effects.approval
        approval_verifier = effects.approval_verifier
    else:
        raise ValueError("binding_mismatch")
    result = asyncio.run(
        execute_gate_d_bounded_acquisition(
            request=request,
            delegate=delegate,
            collector_factory=cast(SyntheticCollectorFactory, collector_factory),
            journal=journal,
            checkpoints=checkpoints,
            operational=type(effects) is GateDOperationalEffects,
            operational_approval=approval,
            operational_approval_verifier=approval_verifier,
        )
    )
    return {
        "evidence_sha256": result.public.manifest_sha256,
        "operation_id": packet.operation_id,
        "lineage_id": packet.lineage_id,
    }


__all__ = ["invoke_gate_d"]
