import pytest

from role_radar.evaluation.r2_operational_capabilities import make_test_capability
from role_radar.evaluation.r2_real_ats_capability import (
    REAL_ATS_FAMILIES,
    REAL_ATS_HOSTS,
    ApprovedRealATSCapability,
    RealATSCapabilityError,
    capability_from_independent_verifier,
    make_test_real_ats_verification,
)
from tests.integration.test_r2_greenhouse_lever_gate_d_bridge import _operational_fixture


class _Verifier:
    def verify_real_ats(self, packet: object, plan: object) -> object:
        return make_test_real_ats_verification(packet, plan)  # type: ignore[arg-type]


def test_real_capability_is_exact_and_verifier_produced(tmp_path) -> None:
    packet, resolved, _factory, _approval = _operational_fixture(tmp_path)
    capability = capability_from_independent_verifier(
        packet,
        resolved.source_plan,
        make_test_capability(packet),
        _Verifier(),
    )
    assert type(capability) is ApprovedRealATSCapability
    assert capability.claims.provider_families == REAL_ATS_FAMILIES
    assert capability.claims.allowed_hosts == REAL_ATS_HOSTS
    assert ApprovedRealATSCapability.__dataclass_params__.frozen
    with pytest.raises(TypeError):
        ApprovedRealATSCapability()  # type: ignore[call-arg]


def test_forged_or_mismatched_verification_is_rejected_before_capability(tmp_path) -> None:
    packet, resolved, _factory, _approval = _operational_fixture(tmp_path)

    class Forged:
        def verify_real_ats(self, _packet: object, _plan: object) -> object:
            return object()

    with pytest.raises(RealATSCapabilityError, match="real_ats_capability_rejected"):
        capability_from_independent_verifier(
            packet,
            resolved.source_plan,
            make_test_capability(packet),
            Forged(),
        )


def test_invalid_packet_and_plan_are_rejected_before_verifier_invocation(tmp_path) -> None:
    packet, resolved, factory, _approval = _operational_fixture(tmp_path)
    calls = 0

    class Verifier:
        def verify_real_ats(self, _packet: object, _plan: object) -> object:
            nonlocal calls
            calls += 1
            return make_test_real_ats_verification(packet, resolved.source_plan)

    object.__setattr__(packet, "operation_id", "")
    with pytest.raises(RealATSCapabilityError):
        capability_from_independent_verifier(
            packet,
            resolved.source_plan,
            factory.capability.production,
            Verifier(),
        )
    assert calls == 0
