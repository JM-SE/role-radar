import json
from dataclasses import replace

from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_gate_d_adapter import invoke_gate_d
from role_radar.evaluation.r2_real_ats_capability import (
    capability_from_independent_verifier,
    make_test_real_ats_verification,
)
from role_radar.evaluation.r2_real_ats_factory import create_test_real_ats_factory
from role_radar.evaluation.r2_real_ats_transport import make_test_real_ats_transport
from tests.integration.test_r2_greenhouse_lever_gate_d_bridge import (
    _ApprovalVerifier,
    _operational_fixture,
)


class _Verifier:
    def verify_real_ats(self, packet: object, plan: object) -> object:
        return make_test_real_ats_verification(packet, plan)  # type: ignore[arg-type]


def test_valid_fake_real_mode_traverses_gate_d_once_and_stops(tmp_path) -> None:
    packet, resolved, old_factory, approval = _operational_fixture(tmp_path)
    capability = capability_from_independent_verifier(
        packet,
        resolved.source_plan,
        old_factory.capability.production,
        _Verifier(),
    )
    transport = make_test_real_ats_transport(
        {
            "/v1/boards/acme/jobs": json.dumps({"jobs": []}).encode(),
            "/v0/postings/acme": b"[]",
        }
    )
    factory = create_test_real_ats_factory(
        capability,
        packet,
        resolved.source_plan,
        transport,
        current_time=packet.window_start,
    )
    resolved_real = replace(resolved, operational_capability=capability)

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return resolved_real

    result = invoke_gate_d(
        packet,
        capability.production,
        Resolver(),
        factory,
        approval,
        _ApprovalVerifier(),
        clock=lambda: packet.window_start,
    )
    assert result["operation_id"] == packet.operation_id
    assert transport.calls == 2
    assert (tmp_path / packet.operation_id / "sealed_pool.jsonl").is_file()
    assert (tmp_path / packet.operation_id / "manifest.json").is_file()
