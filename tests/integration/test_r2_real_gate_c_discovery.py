"""Fake-transport Gate C discovery: unknown boards become a sealed SourcePlan.

No live network, no real credentials, no Source/Job writes. Temporary roots
only, under both network-denial forms via the suite runner.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import httpx
import pytest

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.discovery.contracts import ProviderTier, SearchResponse, TransientSearchHit
from role_radar.discovery.planner_v2 import plan_profile_discovery
from role_radar.discovery.policy import (
    DiscoveryPhraseGrammarV1,
    DiscoveryPolicyV1,
    policy_sha256,
)
from role_radar.discovery.profile_terms import (
    CompiledDiscoveryPhraseV1,
    CompiledDiscoveryTermsV1,
    DiscoveryTermProvenanceV1,
)
from role_radar.discovery.providers.brave import BraveSearchProvider
from role_radar.discovery.providers.tavily import TavilySearchProvider
from role_radar.evaluation.profile_relevant_acquisition.gate_b_preflight import (
    GateBPacket,
    PreflightReport,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_authorization import (
    AcceptedGateBBinding,
    GateCAuthorization,
    GateCProvenance,
    gate_b_packet_sha256,
)
from role_radar.evaluation.profile_relevant_acquisition.gate_c_service import (
    GateCServiceError,
    execute_gate_c_real_discovery,
)
from role_radar.evaluation.profile_relevant_acquisition.real_discovery_capability import (
    RealDiscoveryVerification,
    capability_from_independent_verifier,
    make_test_real_discovery_verification,
)
from role_radar.evaluation.profile_relevant_acquisition.real_gate_c_discovery import (
    RealDiscoveryError,
    run_real_gate_c_discovery,
)

NOW = datetime(2026, 9, 10, 1, tzinfo=UTC)
OPERATION_ID = "11111111-1111-4111-8111-111111111111"
LINEAGE_ID = "22222222-2222-4222-8222-222222222222"


def _packet(root: Path, policy_sha: str) -> GateBPacket:
    value = "c" * 64
    return GateBPacket(
        code_commit_sha256=value,
        namespace="r2-real-discovery-test",
        root=str(root),
        selection_seed="a" * 64,
        partition_seed="b" * 64,
        seed_origin="operator_supplied",
        seed_generated=False,
        profile_id="00000000-0000-0000-0000-000000000001",
        profile_version="1",
        profile_sha256=value,
        policy_id="policy-v1",
        policy_version="1",
        policy_sha256=policy_sha,
        window_start_utc="2026-09-10T00:00:00Z",
        window_end_utc="2026-09-11T00:00:00Z",
        per_board_cap=10,
        per_company_cap=10,
        corpus_count=10,
        pilot_count=2,
        holdout_count=8,
        budget_units=100,
        historical_reference=False,
        authority_reference="new_planned_packet",
    )


def _plan() -> Any:
    policy = DiscoveryPolicyV1.model_validate(
        {
            "schema_version": 1,
            "policy_version": "1",
            "profile_binding": {
                "profile_id": "00000000-0000-0000-0000-000000000001",
                "row_version": 1,
                "schema_version": 1,
                "canonical_profile_sha256": "c" * 64,
            },
            "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
            "groups": {"primary": ["Backend Engineer"]},
            "target_roles": {"backend": {"primary_groups": ["primary"]}},
            "target_titles": {},
        }
    )
    terms = CompiledDiscoveryTermsV1(
        profile_binding=policy.profile_binding,
        policy_version=policy.policy_version,
        policy_sha256=policy_sha256(policy),
        phrases=(
            CompiledDiscoveryPhraseV1(
                "Backend Engineer",
                (DiscoveryTermProvenanceV1("target_roles", "backend", "primary", False),),
            ),
        ),
    )
    return plan_profile_discovery(terms, policy)


def _config() -> Any:
    quota = lambda handle: SimpleNamespace(  # noqa: E731
        enabled=True, units_limit=4, credential_handle=handle
    )
    return SimpleNamespace(
        config_version="config-v1",
        brave_free=quota("brave-free"),
        tavily_free=quota("tavily-free"),
    )


def _bundle(tmp_path: Path) -> tuple[Any, Any, Any, Any]:
    plan = _plan()
    packet = replace(_packet(tmp_path, "c" * 64), policy_sha256=plan.policy_sha256)
    packet_hash = gate_b_packet_sha256(packet)
    expires_at = (datetime.now(UTC) + timedelta(hours=2)).replace(microsecond=0)
    accepted = AcceptedGateBBinding(
        packet,
        packet_hash,
        PreflightReport(
            result="ready",
            code="gate_b_packet_ready",
            code_commit_sha256=packet.code_commit_sha256,
            profile_sha256=packet.profile_sha256,
            policy_sha256=packet.policy_sha256,
            packet_sha256=packet_hash,
        ),
    )
    provenance = GateCProvenance(
        gate_b_packet_sha256=packet_hash,
        candidate_commit_sha256=packet.code_commit_sha256,
        profile_id=packet.profile_id,
        profile_version=packet.profile_version,
        profile_sha256=packet.profile_sha256,
        policy_id=packet.policy_id,
        policy_version=packet.policy_version,
        policy_sha256=packet.policy_sha256,
        query_plan_sha256=plan.plan_sha256,
        namespace=packet.namespace,
        approved_root=packet.root,
        window_start_utc=packet.window_start_utc,
        window_end_utc=packet.window_end_utc,
        cutoff_utc="2026-09-10T12:00:00Z",
        budget_units=packet.budget_units,
    )
    authorization = GateCAuthorization(
        gate="C",
        mode="report-only",
        report_only=True,
        operation_id=OPERATION_ID,
        lineage_id=LINEAGE_ID,
        expires_at_utc=expires_at.isoformat().replace("+00:00", "Z"),
        provenance=provenance,
        per_board_cap=10,
        per_company_cap=10,
        budget_units=100,
        max_brave_requests=4,
        max_tavily_requests=4,
        max_board_candidates=10,
        max_board_verifications=8,
        max_wire_attempts=100,
        artifact_class="offline_private_report_only",
    )
    return authorization, accepted, plan, _config()


class _FakeVerifier:
    def verify_real_discovery(
        self, authorization: Any, accepted_b: Any, plan: Any, config: Any
    ) -> RealDiscoveryVerification:
        return make_test_real_discovery_verification(authorization, accepted_b, plan, config)


class _FakeResolver:
    def __init__(self) -> None:
        self.handles: list[object] = []

    def text(self, handle: object) -> str:
        self.handles.append(handle)
        assert handle in {"brave-free", "tavily-free"}
        return "fake-key"


class _Publication:
    reservation_id = "reservation-1"


class _QuotaAdapter:
    def __init__(self) -> None:
        self.commits = 0
        self.started: list[str] = []

    def reserve_and_start_v2(self, *, operation_key: str, **_kwargs: object) -> _Publication:
        self.started.append(operation_key)
        return _Publication()

    def finalize_v2(self, *, reservation_id: str, **_kwargs: object) -> object:
        return object()

    def revalidate_context_v2(self, *, context: object, **_kwargs: object) -> object:
        return context

    def commit_v2(self) -> None:
        self.commits += 1


class _ManagedProvider:
    entered = 0
    closed = 0

    async def __aenter__(self) -> Any:
        self.entered += 1
        return self

    async def __aexit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.closed += 1


class _BoardProvider(_ManagedProvider):
    def __init__(
        self, urls: tuple[str, ...], provider: Literal["brave", "tavily"] = "brave"
    ) -> None:
        self.urls = urls
        self.provider = provider
        self.calls = 0

    async def search(self, _request: object) -> SearchResponse:
        self.calls += 1
        hits = tuple(
            TransientSearchHit(url=url, rank=index + 1) for index, url in enumerate(self.urls)
        )
        return SearchResponse(
            provider=cast(Any, self.provider),
            tier=ProviderTier.FREE,
            status="succeeded",
            hits=hits,
            result_count=len(hits),
            known_count=len(hits),
        )


class _EmptyProvider(_ManagedProvider):
    def __init__(self, provider: Literal["brave", "tavily"] = "brave") -> None:
        self.provider = provider
        self.calls = 0

    async def search(self, _request: object) -> SearchResponse:
        self.calls += 1
        return SearchResponse(
            provider=cast(Any, self.provider), tier=ProviderTier.FREE, status="empty"
        )


class _EmptyCollector:
    async def collect(self, _snapshot: object, _runtime: object) -> CollectionSuccess:
        return CollectionSuccess(status="ok", jobs=(), metrics=CollectionMetrics())


def _collector_factory(_snapshot: object, _context: object) -> _EmptyCollector:
    return _EmptyCollector()


def _provider_factory(name: str, api_key: str) -> Any:
    assert api_key == "fake-key"
    if name == "brave":
        return _BoardProvider(
            ("https://boards.greenhouse.io/acme", "https://jobs.lever.co/acme"), "brave"
        )
    return _EmptyProvider("tavily")


def test_fake_flow_discovers_greenhouse_and_lever(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    quota = _QuotaAdapter()

    async def _run() -> Any:
        return await run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=quota,
            artifact_root=tmp_path,
            provider_factory=_provider_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )

    result = asyncio.run(
        execute_gate_c_real_discovery(
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            capability=capability,
            discover=_run,
            evidence_root=tmp_path,
            now=NOW,
        )
    )
    assert result.public.result == "completed"
    assert result.source_plan is not None
    families = sorted(item["family"] for item in result.source_plan.source_configs)
    assert families == ["greenhouse", "lever"]
    assert result.public.family_counts == {"family_greenhouse": 1, "family_lever": 1}
    assert result.report is None
    evidence = tmp_path / "gate-c" / plan.plan_sha256 / "real_discovery_evidence.json"
    assert evidence.exists()
    payload = evidence.read_bytes()
    assert b"https://" not in payload
    assert b"boards.greenhouse.io" not in payload
    assert b"jobs.lever.co" not in payload
    for forbidden in (b"canonical_url", b"title", b"snippet", b"answer", b"raw"):
        assert forbidden not in payload


def test_completed_partial_with_verified_sources_persists_bounded_result(
    tmp_path: Path,
) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    quota = _QuotaAdapter()

    async def _discover() -> Any:
        discovered = await run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=quota,
            artifact_root=tmp_path,
            provider_factory=_provider_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )
        counts = dict(discovered.counts or {})
        counts.update(
            unique_board_candidates_seen=10,
            unique_board_candidates_retained=10,
        )
        return replace(
            discovered,
            candidates_seen=10,
            state="completed_partial",
            terminal_code="unique_board_candidates_exhausted",
            counts=counts,
            truncation={
                "unique_board_candidates": True,
                "board_verifications": False,
                "verification_wire_attempts": False,
            },
        )

    result = asyncio.run(
        execute_gate_c_real_discovery(
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            capability=capability,
            discover=_discover,
            evidence_root=tmp_path,
            now=NOW,
        )
    )

    assert result.public.result == "completed_partial"
    assert result.public.budget_status == "bounded_partial"
    assert result.public.reason == "unique_board_candidates_exhausted"
    assert result.source_plan is not None
    assert (tmp_path / "gate-c" / plan.plan_sha256 / "real_discovery_evidence.json").exists()


def test_real_search_providers_are_opened_before_runtime_and_closed_afterward(
    tmp_path: Path,
) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    requests: list[httpx.Request] = []

    async def _handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"web": {"results": [{"url": "https://boards.greenhouse.io/acme"}]}},
            request=request,
        )

    transport = httpx.MockTransport(_handler)
    providers: dict[str, Any] = {}

    def _real_provider_factory(name: str, api_key: str) -> Any:
        provider: Any
        if name == "brave":
            provider = BraveSearchProvider(api_key, transport=transport)
        else:
            provider = TavilySearchProvider(api_key, transport=transport)
        providers[name] = provider
        return provider

    quota = _QuotaAdapter()
    result = asyncio.run(
        run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=quota,
            artifact_root=tmp_path,
            provider_factory=_real_provider_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )
    )

    assert result.state == "completed"
    assert requests
    assert all(request.url.host == "api.search.brave.com" for request in requests)
    assert all(request.method == "GET" for request in requests)
    assert providers["brave"]._client is None
    assert providers["tavily"]._client is None
    assert len(quota.started) == len(requests)


def test_provider_open_failure_closes_previous_provider_before_any_quota_start(
    tmp_path: Path,
) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    brave = _BoardProvider(("https://boards.greenhouse.io/acme",))

    class _FailingOpenProvider:
        provider = "tavily"

        async def __aenter__(self) -> Any:
            raise OSError("client initialization failed")

        async def __aexit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
            raise AssertionError("failed provider must not be closed as opened")

        async def search(self, _request: object) -> SearchResponse:
            raise AssertionError("search must not run")

    quota = _QuotaAdapter()

    def _factory(name: str, _api_key: str) -> Any:
        return brave if name == "brave" else _FailingOpenProvider()

    with pytest.raises(RealDiscoveryError, match="real_discovery_provider_open_failed"):
        asyncio.run(
            run_real_gate_c_discovery(
                capability=capability,
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                resolver=_FakeResolver(),
                quota_adapter=quota,
                artifact_root=tmp_path,
                provider_factory=_factory,
                collector_factory=_collector_factory,
                clock=NOW,
                nonce_source=lambda: b"n" * 32,
                now=NOW,
            )
        )

    assert brave.entered == 1
    assert brave.closed == 1
    assert quota.started == []


def test_provider_factory_failure_is_sanitized_before_any_quota_start(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    brave = _BoardProvider(("https://boards.greenhouse.io/acme",))
    quota = _QuotaAdapter()

    def _factory(name: str, _api_key: str) -> Any:
        if name == "brave":
            return brave
        raise RuntimeError("provider construction failed")

    with pytest.raises(RealDiscoveryError, match="real_discovery_provider_open_failed"):
        asyncio.run(
            run_real_gate_c_discovery(
                capability=capability,
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                resolver=_FakeResolver(),
                quota_adapter=quota,
                artifact_root=tmp_path,
                provider_factory=_factory,
                collector_factory=_collector_factory,
                clock=NOW,
                nonce_source=lambda: b"n" * 32,
                now=NOW,
            )
        )

    assert brave.entered == 1
    assert brave.closed == 1
    assert quota.started == []


def test_provider_real_discovery_error_during_open_is_sanitized(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    brave = _BoardProvider(("https://boards.greenhouse.io/acme",))
    quota = _QuotaAdapter()

    class _FailingOpenProvider:
        provider = "tavily"

        async def __aenter__(self) -> Any:
            raise RealDiscoveryError("inner_provider_error")

        async def __aexit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
            raise AssertionError("failed provider must not be closed as opened")

        async def search(self, _request: object) -> SearchResponse:
            raise AssertionError("search must not run")

    def _factory(name: str, _api_key: str) -> Any:
        return brave if name == "brave" else _FailingOpenProvider()

    with pytest.raises(RealDiscoveryError, match="real_discovery_provider_open_failed"):
        asyncio.run(
            run_real_gate_c_discovery(
                capability=capability,
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                resolver=_FakeResolver(),
                quota_adapter=quota,
                artifact_root=tmp_path,
                provider_factory=_factory,
                collector_factory=_collector_factory,
                clock=NOW,
                nonce_source=lambda: b"n" * 32,
                now=NOW,
            )
        )

    assert brave.entered == 1
    assert brave.closed == 1
    assert quota.started == []


def test_zero_verified_boards_stops_without_plan(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )

    def _empty_factory(name: str, api_key: str) -> Any:
        assert api_key == "fake-key"
        return _EmptyProvider(cast(Any, name))

    async def _run() -> Any:
        return await run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=_QuotaAdapter(),
            artifact_root=tmp_path,
            provider_factory=_empty_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )

    with pytest.raises(GateCServiceError):
        asyncio.run(
            execute_gate_c_real_discovery(
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                capability=capability,
                discover=_run,
                evidence_root=tmp_path,
                now=NOW,
            )
        )


def test_wrong_root_rejected_before_effects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )

    async def _never() -> Any:
        raise AssertionError("discovery must not run")

    with pytest.raises(GateCServiceError):
        asyncio.run(
            execute_gate_c_real_discovery(
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                capability=capability,
                discover=_never,
                evidence_root=tmp_path / "elsewhere",
                now=NOW,
            )
        )


def test_forged_result_binding_rejected(tmp_path: Path) -> None:
    from dataclasses import replace as _replace

    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )

    async def _run() -> Any:
        return await run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=_QuotaAdapter(),
            artifact_root=tmp_path,
            provider_factory=_provider_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )

    genuine = asyncio.run(_run())

    async def _forged_operation() -> Any:
        return _replace(genuine, operation_id="ffffffff-ffff-4fff-bfff-ffffffffffff")

    with pytest.raises(GateCServiceError, match="real_discovery_binding_mismatch"):
        asyncio.run(
            execute_gate_c_real_discovery(
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                capability=capability,
                discover=_forged_operation,
                evidence_root=tmp_path,
                now=NOW,
            )
        )

    async def _forged_plan() -> Any:
        return _replace(genuine, plan_sha256="0" * 64)

    with pytest.raises(GateCServiceError, match="real_discovery_binding_mismatch"):
        asyncio.run(
            execute_gate_c_real_discovery(
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                capability=capability,
                discover=_forged_plan,
                evidence_root=tmp_path,
                now=NOW,
            )
        )


def test_caller_board_arguments_rejected_before_effects(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    calls: list[str] = []

    async def _never() -> Any:
        calls.append("thunk")
        raise AssertionError("discovery must not run")

    with pytest.raises(TypeError):
        asyncio.run(
            execute_gate_c_real_discovery(  # type: ignore[call-arg]
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                capability=capability,
                discover=_never,
                evidence_root=tmp_path,
                boards=["acme"],
                now=NOW,
            )
        )
    assert calls == []

    class _NeverResolver:
        def text(self, handle: object) -> str:
            calls.append("resolver")
            raise AssertionError("credentials must not resolve")

    with pytest.raises(TypeError):
        asyncio.run(
            run_real_gate_c_discovery(  # type: ignore[call-arg]
                capability=capability,
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                resolver=_NeverResolver(),
                quota_adapter=_QuotaAdapter(),
                artifact_root=tmp_path,
                source_configs=[{"family": "greenhouse"}],
                now=NOW,
            )
        )
    assert calls == []


def test_gate_c_plan_is_consumed_unchanged_by_real_ats_factory(tmp_path: Path) -> None:
    import json
    from datetime import timedelta

    from role_radar.evaluation.r2_greenhouse_lever_factory import R2GreenhouseLeverFactory
    from role_radar.evaluation.r2_operational_authorization import OperationPacket
    from role_radar.evaluation.r2_operational_capabilities import make_test_capability
    from role_radar.evaluation.r2_real_ats_capability import (
        capability_from_independent_verifier as ats_capability_from_verifier,
    )
    from role_radar.evaluation.r2_real_ats_capability import (
        make_test_real_ats_verification as make_ats_verification,
    )
    from role_radar.evaluation.r2_real_ats_transport import make_test_real_ats_transport

    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )

    async def _run() -> Any:
        return await run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=_QuotaAdapter(),
            artifact_root=tmp_path,
            provider_factory=_provider_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )

    result = asyncio.run(
        execute_gate_c_real_discovery(
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            capability=capability,
            discover=_run,
            evidence_root=tmp_path,
            now=NOW,
        )
    )
    assert result.source_plan is not None
    gate_c_plan = result.source_plan
    plan_sha_before = gate_c_plan.source_plan_sha256

    start = NOW
    packet = OperationPacket(
        OPERATION_ID,
        "d",
        "a" * 64,
        gate_c_plan.source_plan_sha256,
        "b" * 64,
        "c" * 64,
        "d" * 64,
        "e" * 64,
        gate_c_plan.namespace,
        gate_c_plan.root,
        start,
        start + timedelta(hours=1),
        "1" * 64,
        "2" * 64,
        gate_c_plan.per_board_cap,
        gate_c_plan.per_company_cap,
        10,
        2,
        "r2-capability",
        "approval",
        "3" * 64,
        start + timedelta(minutes=30),
        "nonce",
        ("4" * 64,),
        lineage_id=LINEAGE_ID,
    )
    production = make_test_capability(packet)

    class _ATSVerifier:
        def verify_real_ats(self, _packet: object, _plan: object) -> object:
            return make_ats_verification(packet, gate_c_plan)

    claims = ats_capability_from_verifier(packet, gate_c_plan, production, _ATSVerifier())
    responses = {
        "/v1/boards/acme/jobs": json.dumps({"jobs": []}).encode(),
        "/v0/postings/acme": json.dumps([]).encode(),
    }
    transport = make_test_real_ats_transport(responses)
    factory = R2GreenhouseLeverFactory(claims, packet, gate_c_plan, transport, start)
    snapshots = factory.snapshots()
    assert [snapshot.source_type for snapshot in snapshots] == ["greenhouse", "lever"]
    assert [snapshot.source_key for snapshot in snapshots] == [
        item["source_key"] for item in gate_c_plan.source_configs
    ]
    assert gate_c_plan.source_plan_sha256 == plan_sha_before
    assert transport._allowed_hosts == (
        "boards-api.greenhouse.io",
        "api.lever.co",
        "api.eu.lever.co",
    )


def test_tavily_fallback_attributes_per_provider_counts(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )

    class _FailedBrave(_ManagedProvider):
        provider = "brave"

        def __init__(self) -> None:
            self.calls = 0

        async def search(self, _request: object) -> SearchResponse:
            self.calls += 1
            return SearchResponse(
                provider="brave",
                tier=ProviderTier.FREE,
                status="failed",
                error_code="provider_failed",
            )

    def _fallback_factory(name: str, api_key: str) -> Any:
        assert api_key == "fake-key"
        if name == "brave":
            return _FailedBrave()
        return _BoardProvider(
            ("https://boards.greenhouse.io/acme", "https://jobs.lever.co/acme"), "tavily"
        )

    result = asyncio.run(
        run_real_gate_c_discovery(
            capability=capability,
            authorization=authorization,
            accepted_b=accepted,
            plan=plan,
            config=config,
            resolver=_FakeResolver(),
            quota_adapter=_QuotaAdapter(),
            artifact_root=tmp_path,
            provider_factory=_fallback_factory,
            collector_factory=_collector_factory,
            clock=NOW,
            nonce_source=lambda: b"n" * 32,
            now=NOW,
        )
    )
    assert result.state == "completed"
    assert result.brave_requests == 4
    assert result.tavily_requests == 4
    assert {source.source_type for source in result.verified_sources} == {
        "greenhouse",
        "lever",
    }


def test_non_code_owned_urls_never_reach_verification(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )
    verifier_calls: list[str] = []

    def _counting_collector(_snapshot: object, _context: object) -> Any:
        verifier_calls.append("collect")

        class _Collector:
            async def collect(self, _snap: object, _rt: object) -> CollectionSuccess:
                return CollectionSuccess(status="ok", jobs=(), metrics=CollectionMetrics())

        return _Collector()

    def _foreign_factory(name: str, api_key: str) -> Any:
        assert api_key == "fake-key"
        return _BoardProvider(
            (
                "https://www.linkedin.com/jobs/view/123",
                "https://example.com/jobs/acme",
                "https://boards.greenhouse.io/",
            ),
            name,
        )

    with pytest.raises(RealDiscoveryError):
        asyncio.run(
            run_real_gate_c_discovery(
                capability=capability,
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                resolver=_FakeResolver(),
                quota_adapter=_QuotaAdapter(),
                artifact_root=tmp_path,
                provider_factory=_foreign_factory,
                collector_factory=_counting_collector,
                clock=NOW,
                nonce_source=lambda: b"n" * 32,
                now=NOW,
            )
        )
    assert verifier_calls == []


def test_credential_failure_is_sanitized(tmp_path: Path) -> None:
    authorization, accepted, plan, config = _bundle(tmp_path)
    capability = capability_from_independent_verifier(
        authorization, accepted, plan, config, _FakeVerifier(), now=NOW
    )

    class _BadResolver:
        def text(self, handle: object) -> str:
            raise OSError("missing")

    with pytest.raises(RealDiscoveryError) as excinfo:
        asyncio.run(
            run_real_gate_c_discovery(
                capability=capability,
                authorization=authorization,
                accepted_b=accepted,
                plan=plan,
                config=config,
                resolver=_BadResolver(),
                quota_adapter=_QuotaAdapter(),
                artifact_root=tmp_path,
                provider_factory=_provider_factory,
                collector_factory=_collector_factory,
                clock=NOW,
                nonce_source=lambda: b"n" * 32,
                now=NOW,
            )
        )
    assert excinfo.value.code == "real_discovery_credential_unavailable"
