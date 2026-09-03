"""Typed, non-I/O boundary for synthetic R2 operation artifacts.

This module deliberately contains contracts only.  Resolvers are supplied by
tests (or by a future separately authorised boundary); they never decode or
load an artifact themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from role_radar.discovery.board_candidates import BoardCandidateV2
from role_radar.discovery.planner_v2 import DiscoveryQueryPlanV2
from role_radar.evaluation.profile_relevance.contracts import (
    MaterializedPayloads,
    PreviewComputationResult,
)
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    GateDResult,
    SourceCheckpoint,
    SyntheticCollectorFactory,
    SyntheticTransport,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    SeedInputs,
    SyntheticTestAdapter,
)
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import FrozenBenchmark
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import GateCResult
from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import (
    GateDAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_e_authorization import (
    GateEAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_f_authorization import (
    GateFAuthorizationRequest,
)
from role_radar.evaluation.profile_relevant_acquisition.journal import AcquisitionJournal
from role_radar.evaluation.profile_relevant_acquisition.post_c_preregistration_contracts import (
    PostCPreregistrationRequest,
    PostCPreregistrationSeal,
    PrivateSealWriter,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import SourcePlan
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability


@dataclass(frozen=True, slots=True)
class ResolvedGateCInput:
    authorization: GateCAuthorization
    accepted_b: AcceptedGateBBinding
    plan: DiscoveryQueryPlanV2
    evidence_root: Path
    operation_id: str
    lineage_id: str
    packet_sha256: str


@dataclass(frozen=True, slots=True)
class ResolvedPostCInput:
    request: PostCPreregistrationRequest
    operation_id: str
    lineage_id: str
    source_plan_sha256: str
    gate_c_result: GateCResult


@dataclass(frozen=True, slots=True)
class ResolvedGateDInput:
    request: GateDAuthorizationRequest
    operation_id: str
    lineage_id: str
    source_plan: SourcePlan
    post_c_seal: PostCPreregistrationSeal
    seeds: SeedInputs
    window_start_utc: str
    window_end_utc: str
    cutoff_utc: str
    source_cap: int
    quota: int
    cardinality: int
    budget: int


@dataclass(frozen=True, slots=True)
class ResolvedGateEInput:
    request: GateEAuthorizationRequest
    operation_id: str
    lineage_id: str
    gate_d_result: GateDResult
    source_plan_sha256: str


@dataclass(frozen=True, slots=True)
class ResolvedGateFInput:
    request: GateFAuthorizationRequest
    operation_id: str
    lineage_id: str
    destination_root: Path
    source_plan_sha256: str
    gate_d_result: GateDResult
    gate_e_result: PreviewComputationResult


class R2GateCResolver(Protocol):
    def resolve_gate_c(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> ResolvedGateCInput: ...


class R2PostCResolver(Protocol):
    def resolve_post_c(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> ResolvedPostCInput: ...


class R2GateDResolver(Protocol):
    def resolve_gate_d(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> ResolvedGateDInput: ...


class R2GateEResolver(Protocol):
    def resolve_gate_e(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> ResolvedGateEInput: ...


class R2GateFResolver(Protocol):
    def resolve_gate_f(
        self, packet: OperationPacket, capability: ProductionR2Capability
    ) -> ResolvedGateFInput: ...


class R2OfficialProvider(Protocol):
    offline: bool

    def official_board_configurations(
        self, plan: DiscoveryQueryPlanV2
    ) -> tuple[BoardCandidateV2, ...]: ...


class R2PrivateSealWriter(PrivateSealWriter, Protocol):
    pass


@dataclass(frozen=True, slots=True)
class GateDOfflineEffects:
    delegate: SyntheticTransport
    collector_factory: SyntheticCollectorFactory
    journal: AcquisitionJournal
    test_only_adapter: SyntheticTestAdapter
    checkpoints: tuple[SourceCheckpoint, ...] = ()


class R2GateDOfflineFactory(Protocol):
    def create(self, request: GateDAuthorizationRequest) -> GateDOfflineEffects: ...


class R2Materializer(Protocol):
    def __call__(self, **kwargs: object) -> MaterializedPayloads: ...


class R2Freezer(Protocol):
    def __call__(self, **kwargs: object) -> FrozenBenchmark: ...


__all__ = [name for name in globals() if name.startswith(("Resolved", "R2", "GateD"))]
