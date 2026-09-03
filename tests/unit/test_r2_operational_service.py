from datetime import UTC, datetime, timedelta

from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import IndependentCapabilityVerifier
from role_radar.evaluation.r2_operational_service import GateInvokers, GateName, dispatch_one_gate


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
    capability = IndependentCapabilityVerifier().verify("capability", packet().source_plan_sha256)
    invokers = GateInvokers(gate, gate, gate, gate, gate)
    result = dispatch_one_gate(
        packet=packet(),
        capability=capability,
        verifier=Verifier(),
        invokers=invokers,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result == {"result": "stopped", "code": "gate_completed", "gate": "c"}
    assert gate.calls == 1


def test_default_service_is_blocked_without_effect() -> None:
    capability = IndependentCapabilityVerifier().verify("capability", packet().source_plan_sha256)
    result = dispatch_one_gate(
        packet=packet(),
        capability=capability,
        verifier=Verifier(),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert result == {"result": "blocked", "code": "blocked"}


def test_typed_invokers_select_each_gate_without_successor() -> None:
    invokers = GateInvokers(*(Gate() for _ in range(5)))
    selected = tuple(
        invokers.for_gate(gate)
        for gate in (GateName.C, GateName.POST_C, GateName.D, GateName.E, GateName.F)
    )
    assert len({id(item) for item in selected}) == 5
