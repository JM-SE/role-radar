import pytest

from role_radar.evaluation.r2_greenhouse_lever_factory import R2GreenhouseLeverFactory
from role_radar.evaluation.r2_operational_capabilities import make_test_capability
from role_radar.evaluation.r2_real_ats_capability import (
    capability_from_independent_verifier,
    make_test_real_ats_verification,
)
from role_radar.evaluation.r2_real_ats_factory import (
    RealATSCollectorFactory,
    create_test_real_ats_factory,
)
from role_radar.evaluation.r2_real_ats_transport import make_test_real_ats_transport
from tests.integration.test_r2_greenhouse_lever_gate_d_bridge import _operational_fixture


class _Verifier:
    def verify_real_ats(self, packet: object, plan: object) -> object:
        return make_test_real_ats_verification(packet, plan)  # type: ignore[arg-type]


def test_factory_is_named_fixed_mapping_and_only_accepts_sealed_fake(tmp_path) -> None:
    packet, resolved, _old_factory, _approval = _operational_fixture(tmp_path)
    capability = capability_from_independent_verifier(
        packet,
        resolved.source_plan,
        make_test_capability(packet),
        _Verifier(),
    )
    transport = make_test_real_ats_transport({})
    factory = create_test_real_ats_factory(
        capability,
        packet,
        resolved.source_plan,
        transport,
        current_time=packet.window_start,
    )
    assert RealATSCollectorFactory is R2GreenhouseLeverFactory
    assert type(factory) is R2GreenhouseLeverFactory
    assert factory.capability is capability
    with pytest.raises(TypeError):
        create_test_real_ats_factory(capability, packet, resolved.source_plan, object())  # type: ignore[arg-type]
