from datetime import UTC, datetime, timedelta

from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import ProductionR2Capability
from role_radar.evaluation.r2_operational_service import dispatch_one_gate


def packet() -> OperationPacket:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return OperationPacket(
        "op-1",
        "c",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "f" * 64,
        "namespace",
        "root",
        now,
        now + timedelta(hours=1),
        "a" * 64,
        "b" * 64,
        1,
        1,
        1,
        1,
        "capability",
        "approval",
        "a" * 64,
        now + timedelta(hours=1),
        "nonce",
        ("a" * 64,),
    )


class Verifier:
    def verify(self, _packet: object, _reference: str) -> bool:
        return True


class Gate:
    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, _packet: object, _capability: object) -> dict[str, object]:
        self.calls += 1
        return {"gate": "c"}


def test_dispatches_one_gate_then_stops() -> None:
    gate = Gate()
    result = dispatch_one_gate(
        packet=packet(),
        capability=ProductionR2Capability("capability", packet().source_plan_sha256, True),
        verifier=Verifier(),
        gate_service=gate,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result == {"result": "stopped", "code": "gate_completed", "gate": "c"}
    assert gate.calls == 1


def test_default_service_is_blocked_without_effect() -> None:
    result = dispatch_one_gate(
        packet=packet(),
        capability=ProductionR2Capability("capability", packet().source_plan_sha256, True),
        verifier=Verifier(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result == {"result": "blocked", "code": "blocked"}
