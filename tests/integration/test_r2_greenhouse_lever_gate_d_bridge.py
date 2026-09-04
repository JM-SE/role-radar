import json
import shutil
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from role_radar.collectors.registry import CollectorContext
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    SyntheticTransport,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    ExternalApprovalBinding,
    SeedInputs,
)
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
from role_radar.evaluation.r2_operational_artifacts import ResolvedGateDInput
from role_radar.evaluation.r2_operational_authorization import OperationPacket
from role_radar.evaluation.r2_operational_capabilities import make_test_capability
from role_radar.evaluation.r2_operational_gate_d_adapter import invoke_gate_d
from role_radar.evaluation.r2_real_ats_capability import (
    capability_from_independent_verifier,
    make_test_real_ats_verification,
)
from role_radar.evaluation.r2_real_ats_transport import make_test_real_ats_transport
from tests.unit.test_profile_relevant_gate_d_bounded_acquisition import _request


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
    factory = R2GreenhouseLeverFactory(capability, packet, plan, transport, packet.window_start)
    journal = AcquisitionJournal(operation_id=packet.operation_id, root=Path(plan.root))
    wrapped = JournaledAsyncTransport(
        delegate=transport, journal=journal, source_id="source", operation_id=packet.operation_id
    )
    from role_radar.collectors.greenhouse import GreenhouseCollector

    collector = factory.create(factory.snapshots()[0], CollectorContext(wrapped, None))
    assert type(collector) is GreenhouseCollector
    assert transport._allowed_hosts == ("boards-api.greenhouse.io",)


def test_invalid_plan_is_rejected_before_transport_binding() -> None:
    packet = _packet()
    valid_plan = _plan()
    plan = build_source_plan(
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
                "family": "jobicy",
                "source_key": "jobicy:acme",
                "configuration_version": 1,
                "configuration": {"site": "acme"},
            },
        ),
    )
    capability = R2GreenhouseLeverCapability(
        make_test_verification(packet, valid_plan), make_test_capability(packet)
    )
    transport = make_test_transport({"/v1/boards/acme/jobs": b'{"jobs":[]}'})
    with pytest.raises(ValueError):
        R2GreenhouseLeverFactory(capability, packet, plan, transport, packet.window_start)
    assert transport.calls == 0
    assert transport._allowed_hosts == ()


@pytest.mark.parametrize(
    ("family", "configuration_version", "configuration"),
    (
        ("jobicy", 1, {"site": "acme"}),
        ("greenhouse", True, {"board_token": "acme"}),
        ("greenhouse", 1, {"board_token": "acme", "authorization": "secret"}),
    ),
)
def test_rejected_family_bool_or_credential_config_has_zero_transport_effect(
    family: str, configuration_version: int | bool, configuration: dict[str, str]
) -> None:
    packet = _packet()
    valid_plan = _plan()
    invalid_plan = build_source_plan(
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
                "family": family,
                "source_key": "greenhouse:acme",
                "configuration_version": configuration_version,
                "configuration": configuration,
            },
        ),
    )
    capability = R2GreenhouseLeverCapability(
        make_test_verification(packet, valid_plan), make_test_capability(packet)
    )
    transport = make_test_transport({"/v1/boards/acme/jobs": b'{"jobs": []}'})
    with pytest.raises(ValueError):
        R2GreenhouseLeverFactory(capability, packet, invalid_plan, transport, packet.window_start)
    assert transport.calls == 0
    assert transport._allowed_hosts == ()


class _ApprovalVerifier:
    def verify(self, approval: object, digest: str) -> bool:
        return isinstance(approval, ExternalApprovalBinding) and approval.artifact_sha256 == digest


def _operational_fixture(
    root: Path,
) -> tuple[OperationPacket, object, R2GreenhouseLeverFactory, ExternalApprovalBinding]:
    request = replace(_request(root), test_only_adapter=None)
    # Gate C setup uses the same temporary evidence root; remove only its
    # generated operation directory so Gate D gets an isolated journal, pool,
    # and manifest.
    shutil.rmtree(root / request.operation_id, ignore_errors=True)
    post = request.post_c_request
    plan = post.source_plan
    start = datetime.fromisoformat(request.window_start_utc.replace("Z", "+00:00"))
    end = datetime.fromisoformat(request.window_end_utc.replace("Z", "+00:00"))
    packet = OperationPacket(
        request.operation_id,
        "d",
        request.current_commit_sha256,
        plan.source_plan_sha256,
        post.accepted_gate_b.packet_sha256,
        post.accepted_gate_b.packet.profile_sha256,
        post.accepted_gate_b.packet.policy_sha256,
        post.query_plan.plan_sha256,
        request.namespace,
        str(root),
        start,
        end,
        request.seeds.selection_seed,
        request.seeds.partition_seed,
        request.per_board_cap,
        1,
        10,
        request.budget_units,
        "r2-capability",
        "approval",
        "3" * 64,
        end,
        "nonce",
        ("4" * 64,),
        lineage_id=request.lineage_id,
    )
    production = make_test_capability(packet)

    class OfflineRealATSVerifier:
        def verify_real_ats(self, _packet: object, _plan: object) -> object:
            return make_test_real_ats_verification(packet, plan)

    claims = capability_from_independent_verifier(
        packet,
        plan,
        production,
        OfflineRealATSVerifier(),
    )
    responses = {
        "/v1/boards/acme/jobs": json.dumps(
            {
                "jobs": [
                    {
                        "id": 101,
                        "title": "Backend Engineer",
                        "location": {"name": "Remote"},
                        "absolute_url": "https://boards.greenhouse.io/acme/jobs/101",
                        "updated_at": "2026-08-01T12:00:00Z",
                        "content": "Build APIs",
                    }
                ]
            }
        ).encode(),
        "/v0/postings/acme": json.dumps(
            [
                {
                    "id": "201",
                    "text": "Platform Engineer",
                    "categories": {"location": "Remote"},
                    "descriptionPlain": "Build APIs",
                    "hostedUrl": "https://jobs.lever.co/acme/201",
                    "applyUrl": "https://jobs.lever.co/acme/201/apply",
                }
            ]
        ).encode(),
    }
    transport = make_test_real_ats_transport(responses)
    factory = R2GreenhouseLeverFactory(claims, packet, plan, transport, start)
    from role_radar.evaluation.profile_relevant_acquisition.gate_d_authorization import (
        authorize_gate_d,
    )

    authorized = authorize_gate_d(request, now=start, allow_operational=True)
    approval = ExternalApprovalBinding(
        authorized.scaffold.provenance_sha256,
        "5" * 64,
        "external-approver",
        b"offline-approval-token",
    )
    return (
        packet,
        ResolvedGateDInput(
            request,
            request.operation_id,
            request.lineage_id,
            plan,
            request.post_c_seal,
            request.seeds,
            request.window_start_utc,
            request.window_end_utc,
            request.cutoff_utc,
            request.per_board_cap,
            1,
            10,
            request.budget_units,
            claims,
        ),
        factory,
        approval,
    )


def test_invoke_gate_d_operational_bridge_is_offline_bounded_and_sealed(tmp_path: Path) -> None:
    packet, resolved, factory, approval = _operational_fixture(tmp_path)

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return resolved

    # The real adapter branch constructs the named collector factory and runs both
    # existing bounded collectors; no product DB or legacy transport is involved.
    result = invoke_gate_d(
        packet,
        factory.capability.production,
        Resolver(),
        factory,
        approval,
        _ApprovalVerifier(),
        clock=lambda: packet.window_start,
    )
    op_dir = tmp_path / packet.operation_id
    manifest = json.loads((op_dir / "manifest.json").read_text())
    pool = (op_dir / "sealed_pool.jsonl").read_bytes()
    assert result["operation_id"] == packet.operation_id
    assert manifest["observed"] == manifest["new_to_pool"] == 2
    assert manifest["durable_intents"] == manifest["known_terminal_outcomes"] == 2
    assert manifest["budget_consumed"] == manifest["collector_wire_attempts"] == 2
    assert pool.count(b"\n") == 2
    assert factory.transport._allowed_hosts == (
        "boards-api.greenhouse.io",
        "api.lever.co",
        "api.eu.lever.co",
    )
    assert factory.transport.requests == [
        ("boards-api.greenhouse.io", "/v1/boards/acme/jobs"),
        ("api.lever.co", "/v0/postings/acme"),
    ]
    assert factory.transport.calls == 2
    assert not any(secret in pool for secret in (b"candidate", b"email", b"token"))


@pytest.mark.parametrize("position", ["before", "after"])
def test_invoke_gate_d_rejects_outside_window_before_any_effects(
    tmp_path: Path, position: str
) -> None:
    packet, resolved, factory, approval = _operational_fixture(tmp_path)
    calls = 0

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            nonlocal calls
            calls += 1
            return resolved

    check = (
        packet.window_start - timedelta(seconds=1)
        if position == "before"
        else packet.window_cutoff + timedelta(seconds=1)
    )
    allowed_hosts = factory.transport._allowed_hosts
    with pytest.raises(ValueError, match=r"^gate_d_window_inactive$"):
        invoke_gate_d(
            packet,
            factory.capability.production,
            Resolver(),
            factory,
            approval,
            _ApprovalVerifier(),
            clock=lambda: check,
        )
    assert calls == 1
    assert factory.transport.calls == 0
    assert factory.transport._allowed_hosts == allowed_hosts
    assert not (tmp_path / packet.operation_id).exists()


def test_invoke_gate_d_rejects_capability_before_resolver_or_transport(tmp_path: Path) -> None:
    packet, resolved, factory, approval = _operational_fixture(tmp_path)
    calls = 0

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            nonlocal calls
            calls += 1
            return resolved

    with pytest.raises((AttributeError, ValueError)):
        invoke_gate_d(
            packet,
            make_test_capability(replace(packet, source_plan_sha256="e" * 64)),
            Resolver(),
            factory,
            approval,
            _ApprovalVerifier(),
            clock=lambda: packet.window_start,
        )
    assert calls == 0
    assert factory.transport.calls == 0


def test_invoke_gate_d_rejects_missing_approval_before_effects(tmp_path: Path) -> None:
    packet, resolved, factory, _approval = _operational_fixture(tmp_path)

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return resolved

    with pytest.raises(ValueError, match="binding_mismatch"):
        invoke_gate_d(
            packet,
            factory.capability.production,
            Resolver(),
            factory,
            clock=lambda: packet.window_start,
        )
    assert factory.transport.calls == 0


def test_invoke_gate_d_rejects_forged_factory_before_transport(tmp_path: Path) -> None:
    packet, resolved, factory, approval = _operational_fixture(tmp_path)

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return resolved

    with pytest.raises(ValueError, match="r2_operational_factory_required"):
        invoke_gate_d(
            packet,
            factory.capability.production,
            Resolver(),
            object(),
            approval,
            _ApprovalVerifier(),
            clock=lambda: packet.window_start,
        )
    assert factory.transport.calls == 0


def test_invoke_gate_d_revalidates_post_c_before_factory_or_journal(tmp_path: Path) -> None:
    packet, resolved, factory, approval = _operational_fixture(tmp_path)
    object.__setattr__(resolved.request.post_c_request, "artifact_class", "synthetic")

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return resolved

    with pytest.raises(ValueError, match=r"^binding_mismatch$"):
        invoke_gate_d(
            packet,
            factory.capability.production,
            Resolver(),
            factory,
            approval,
            _ApprovalVerifier(),
            clock=lambda: packet.window_start,
        )
    assert factory.transport.calls == 0
    assert not (tmp_path / packet.operation_id).exists()


def test_legacy_capability_is_rejected_from_real_operational_gate_d(tmp_path: Path) -> None:
    packet, resolved, _factory, approval = _operational_fixture(tmp_path)
    legacy = R2GreenhouseLeverCapability(
        make_test_verification(packet, resolved.source_plan),
        resolved.operational_capability.production,  # type: ignore[union-attr]
    )
    legacy_factory = R2GreenhouseLeverFactory(
        legacy,
        packet,
        resolved.source_plan,
        make_test_transport({"/v1/boards/acme/jobs": b'{"jobs": []}'}),
        packet.window_start,
    )
    legacy_resolved = replace(resolved, operational_capability=legacy)

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return legacy_resolved

    with pytest.raises(ValueError, match=r"^binding_mismatch$"):
        invoke_gate_d(
            packet,
            legacy.production,
            Resolver(),
            legacy_factory,
            approval,
            _ApprovalVerifier(),
            clock=lambda: packet.window_start,
        )
    assert legacy_factory.transport.calls == 0
    assert not (tmp_path / packet.operation_id).exists()


def test_mismatched_top_level_b_digest_stops_before_all_operational_effects(
    tmp_path: Path,
) -> None:
    packet, resolved, factory, approval = _operational_fixture(tmp_path)
    object.__setattr__(packet, "b_ready_sha256", "e" * 64)

    class Resolver:
        def resolve_gate_d(self, _packet: OperationPacket, _capability: object) -> object:
            return resolved

    with pytest.raises(ValueError, match=r"^binding_mismatch$"):
        invoke_gate_d(
            packet,
            factory.capability.production,
            Resolver(),
            factory,
            approval,
            _ApprovalVerifier(),
            clock=lambda: packet.window_start,
        )
    assert factory.transport.calls == 0
    assert not (tmp_path / packet.operation_id).exists()
