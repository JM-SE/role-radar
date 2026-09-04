import httpx
import pytest

from role_radar.evaluation.r2_operational_capabilities import make_test_capability
from role_radar.evaluation.r2_real_ats_capability import (
    capability_from_independent_verifier,
    make_test_real_ats_verification,
)
from role_radar.evaluation.r2_real_ats_transport import (
    RealATSTransport,
    RealATSTransportError,
    make_real_ats_transport,
    make_test_real_ats_transport,
)
from tests.integration.test_r2_greenhouse_lever_gate_d_bridge import _operational_fixture


class _Verifier:
    def verify_real_ats(self, packet: object, plan: object) -> object:
        return make_test_real_ats_verification(packet, plan)  # type: ignore[arg-type]


def _capability(tmp_path):
    packet, resolved, _factory, _approval = _operational_fixture(tmp_path)
    return packet, capability_from_independent_verifier(
        packet,
        resolved.source_plan,
        make_test_capability(packet),
        _Verifier(),
    )


def test_real_transport_is_unavailable_by_default_and_factory_bound(tmp_path) -> None:
    packet, capability = _capability(tmp_path)
    with pytest.raises(TypeError):
        RealATSTransport()  # type: ignore[call-arg]
    transport = make_test_real_ats_transport({"/v1/boards/acme/jobs": b'{"jobs": []}'})
    with pytest.raises(RealATSTransportError):
        transport._seal_hosts(
            ("example.invalid",),
            capability.claims.source_configs,
            budget=capability.claims.budget,
            timeout_seconds=capability.claims.timeout_seconds,
            window_start=capability.claims.window_start,
            window_cutoff=capability.claims.window_cutoff,
            expires_at=capability.claims.expires_at,
            current_time=packet.window_start,
        )
    production = make_real_ats_transport(capability)
    assert production._allowed_hosts == capability.claims.allowed_hosts
    assert production._allowed_hosts == (
        "boards-api.greenhouse.io",
        "api.lever.co",
        "api.eu.lever.co",
    )
    assert packet.operation_id


@pytest.mark.asyncio
async def test_offline_real_transport_rejects_unbound_host_without_delegate(tmp_path) -> None:
    packet, capability = _capability(tmp_path)
    transport = make_test_real_ats_transport({})
    transport._seal_hosts(
        capability.claims.allowed_hosts,
        capability.claims.source_configs,
        budget=capability.claims.budget,
        timeout_seconds=capability.claims.timeout_seconds,
        window_start=capability.claims.window_start,
        window_cutoff=capability.claims.window_cutoff,
        expires_at=capability.claims.expires_at,
        current_time=packet.window_start,
    )
    import httpx

    with pytest.raises(RealATSTransportError, match="real_ats_host_rejected"):
        await transport.handle_async_request(httpx.Request("GET", "https://example.invalid/"))
    assert transport.calls == 1


@pytest.mark.asyncio
async def test_fake_transport_rejects_streaming_body_and_non_plan_route(tmp_path) -> None:
    packet, capability = _capability(tmp_path)
    transport = make_test_real_ats_transport({})
    transport._seal_hosts(
        capability.claims.allowed_hosts,
        capability.claims.source_configs,
        budget=capability.claims.budget,
        timeout_seconds=capability.claims.timeout_seconds,
        window_start=capability.claims.window_start,
        window_cutoff=capability.claims.window_cutoff,
        expires_at=capability.claims.expires_at,
        current_time=packet.window_start,
    )
    streaming = httpx.Request(
        "GET",
        "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
        content=iter((b"not-empty",)),
        extensions={"timeout": {"connect": 10, "read": 30, "write": 10, "pool": 10}},
    )
    wrong_route = httpx.Request(
        "GET",
        "https://boards-api.greenhouse.io/v1/boards/other/jobs?content=true",
        extensions={"timeout": {"connect": 10, "read": 30, "write": 10, "pool": 10}},
    )
    for request in (streaming, wrong_route):
        with pytest.raises(RealATSTransportError):
            await transport.handle_async_request(request)
    assert transport.calls == 2


def test_fake_transport_rejects_oversized_fixed_response() -> None:
    from role_radar.evaluation.r2_real_ats_transport import REAL_ATS_WIRE_LIMIT_BYTES

    with pytest.raises(RealATSTransportError, match="real_ats_response_limit"):
        make_test_real_ats_transport(
            {"/v1/boards/acme/jobs": b"x" * (REAL_ATS_WIRE_LIMIT_BYTES + 1)}
        )
