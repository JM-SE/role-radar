from datetime import UTC, datetime, timedelta
from pathlib import Path

from role_radar.collectors.registry import CollectorContext
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    SyntheticTransport,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import SeedInputs
from role_radar.evaluation.profile_relevant_acquisition.journal import AcquisitionJournal
from role_radar.evaluation.profile_relevant_acquisition.journaled_transport import (
    JournaledAsyncTransport,
)
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    SourcePlanBudget,
    build_source_plan,
)
from role_radar.evaluation.r2_greenhouse_lever_capability import (
    R2GreenhouseLeverCapability,
    make_test_verification,
)
from role_radar.evaluation.r2_greenhouse_lever_factory import (
    R2GreenhouseLeverFactory,
    make_test_transport,
)
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import make_test_capability


def _packet() -> OperationPacket:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return OperationPacket(
        "op-bridge",
        "d",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        "f" * 64,
        "bridge-namespace",
        "/tmp/bridge-evidence",
        now,
        now + timedelta(hours=1),
        "1" * 64,
        "2" * 64,
        1,
        1,
        1,
        1,
        "r2-capability",
        "approval",
        "3" * 64,
        now + timedelta(hours=1),
        "nonce",
        ("4" * 64,),
    )


def _plan() -> object:
    return build_source_plan(
        namespace="bridge-namespace",
        root="/tmp/bridge-evidence",
        per_board_cap=1,
        per_company_cap=1,
        budget=SourcePlanBudget("bridge-budget", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-bridge",
        lineage_id="lineage",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )


def test_existing_gate_d_offline_delegate_remains_concrete_synthetic() -> None:
    delegate = SyntheticTransport()
    assert type(delegate) is SyntheticTransport
    assert delegate.calls == 0


def test_operational_factory_constructs_exact_greenhouse_collector_offline() -> None:
    packet = _packet()
    plan = _plan()
    capability = R2GreenhouseLeverCapability(
        make_test_verification(packet, plan), make_test_capability(packet)
    )
    transport = make_test_transport({"/v1/boards/acme/jobs": b'{"jobs":[]}'})
    factory = R2GreenhouseLeverFactory(capability, packet, plan, transport)
    journal = AcquisitionJournal(operation_id=packet.operation_id, root=Path(plan.root))
    wrapped = JournaledAsyncTransport(
        delegate=transport, journal=journal, source_id="source", operation_id=packet.operation_id
    )
    from role_radar.collectors.greenhouse import GreenhouseCollector

    collector = factory.create(factory.snapshots()[0], CollectorContext(wrapped, None))
    assert type(collector) is GreenhouseCollector
    assert transport._allowed_hosts == ("boards-api.greenhouse.io",)
