"""The sole F10.1F transition coordinator.

The local gate modules are intentionally test adapters and cannot be used as a
production transition API.  This coordinator is the only code path that owns
the order ``preflight -> C -> post-C -> D -> E -> F -> freeze`` and it requires
an explicit synthetic adapter while R1 remains non-executable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from role_radar.evaluation.profile_relevance.contracts import PreviewComputationResult
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import GateDResult
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    F10_1FHandoff,
    RuntimeEvidence,
    SyntheticTestAdapter,
)
from role_radar.evaluation.profile_relevant_acquisition.freeze_runtime import FrozenBenchmark
from role_radar.evaluation.profile_relevant_acquisition.preflight_runtime import (
    PreflightEvidence,
    run_preflight,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import SourcePlan


class CoordinatorError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


GateCStep = Callable[[PreflightEvidence], RuntimeEvidence]
PostCStep = Callable[[RuntimeEvidence, SourcePlan], RuntimeEvidence]
GateDStep = Callable[[RuntimeEvidence, SourcePlan], Awaitable[GateDResult]]
GateEStep = Callable[[RuntimeEvidence, GateDResult], PreviewComputationResult]
GateFStep = Callable[[RuntimeEvidence, PreviewComputationResult], F10_1FHandoff]
FreezeStep = Callable[[F10_1FHandoff], FrozenBenchmark]


@dataclass(frozen=True, slots=True)
class CoordinatorSteps:
    """Typed stage seams; each is supplied by the approved local adapter."""

    gate_c: GateCStep
    post_c: PostCStep
    gate_d: GateDStep
    gate_e: GateEStep
    gate_f: GateFStep
    freeze: FreezeStep


@dataclass(frozen=True, slots=True)
class CoordinatorResult:
    """Complete terminal result of one ordered synthetic transition run."""

    preflight: PreflightEvidence
    gate_c: RuntimeEvidence
    post_c: RuntimeEvidence
    gate_d: GateDResult
    gate_e: PreviewComputationResult
    gate_f: F10_1FHandoff
    frozen: FrozenBenchmark


def _require_stage(value: object, gate: str) -> RuntimeEvidence:
    if not isinstance(value, RuntimeEvidence) or value.gate != gate or not value.stopped:
        raise CoordinatorError(f"coordinator_{gate.lower().replace('-', '_')}_handoff_invalid")
    return value


async def run_authoritative_f10_1f(
    *,
    provenance_bytes: bytes,
    challenge_bytes: bytes,
    source_plan: SourcePlan,
    steps: CoordinatorSteps,
    test_only_adapter: SyntheticTestAdapter,
) -> CoordinatorResult:
    """Run one bounded ordered transition; no production branch exists in R1."""

    if not isinstance(test_only_adapter, SyntheticTestAdapter):
        raise CoordinatorError("coordinator_synthetic_adapter_required")
    if not isinstance(source_plan, SourcePlan):
        raise CoordinatorError("coordinator_source_plan_invalid")
    preflight = run_preflight(
        provenance_bytes=provenance_bytes,
        challenge_bytes=challenge_bytes,
        expected_gate="C",
    )
    try:
        gate_c = _require_stage(steps.gate_c(preflight), "C")
        post_c = _require_stage(steps.post_c(gate_c, source_plan), "post-C")
        gate_d = await steps.gate_d(post_c, source_plan)
        if not isinstance(gate_d, GateDResult):
            raise CoordinatorError("coordinator_d_handoff_invalid")
        gate_e = steps.gate_e(post_c, gate_d)
        if not isinstance(gate_e, PreviewComputationResult):
            raise CoordinatorError("coordinator_e_handoff_invalid")
        gate_f = steps.gate_f(post_c, gate_e)
        if not isinstance(gate_f, F10_1FHandoff):
            raise CoordinatorError("coordinator_f_handoff_invalid")
        frozen = steps.freeze(gate_f)
        if not isinstance(frozen, FrozenBenchmark) or not frozen.verified:
            raise CoordinatorError("coordinator_freeze_handoff_invalid")
    except CoordinatorError:
        raise
    except Exception as exc:
        raise CoordinatorError("coordinator_transition_failed") from exc
    return CoordinatorResult(
        preflight=preflight,
        gate_c=gate_c,
        post_c=post_c,
        gate_d=gate_d,
        gate_e=gate_e,
        gate_f=gate_f,
        frozen=frozen,
    )


__all__ = [
    "CoordinatorError",
    "CoordinatorResult",
    "CoordinatorSteps",
    "run_authoritative_f10_1f",
]
