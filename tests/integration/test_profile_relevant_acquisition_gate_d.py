"""Offline Gate D integration: mixed-board broad pool and reconciliation."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext
from role_radar.domain.dto import RawJob
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    AcquisitionError,
    AcquisitionScaffoldConfig,
    SourceCheckpoint,
    SyntheticTransport,
    assert_mixed_board_sealed,
    mark_synthetic_capability,
    run_gate_d_broad_acquisition,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    SeedInputs,
    synthetic_test_adapter,
)
from role_radar.evaluation.profile_relevant_acquisition.journal import AcquisitionJournal
from role_radar.evaluation.profile_relevant_acquisition.source_plan import (
    SourcePlanBudget,
    build_source_plan,
)


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, request=request, content=b'{"jobs":[]}')


@mark_synthetic_capability
class FakeBroadCollector:
    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        self.transport = transport

    async def collect(
        self, snapshot: SourceSnapshot, runtime: CollectorRuntime
    ) -> CollectionSuccess:
        assert runtime.transport is self.transport
        assert runtime.budget is not None
        assert runtime.budget.acquire()
        response = await self.transport.handle_async_request(
            httpx.Request("GET", "https://boards-api.greenhouse.io/v1/boards/acme/jobs")
        )
        assert response.status_code == 200
        now = datetime(2026, 8, 25, tzinfo=UTC)
        jobs = (
            RawJob(
                source="greenhouse",
                external_id="relevant-1",
                source_url="https://boards.greenhouse.io/acme/jobs/1",
                application_url="https://boards.greenhouse.io/acme/jobs/1",
                title="Senior Engineer",
                company="Acme",
                location="Remote",
                description="Relevant board item",
                collected_at=now,
            ),
            RawJob(
                source="greenhouse",
                external_id="unrelated-1",
                source_url="https://boards.greenhouse.io/acme/jobs/2",
                application_url="https://boards.greenhouse.io/acme/jobs/2",
                title="Office Coordinator",
                company="Acme",
                location="Remote",
                description="Unrelated board item",
                collected_at=now,
            ),
        )
        return CollectionSuccess(
            status="ok",
            jobs=jobs,
            metrics=CollectionMetrics(
                logical_requests=1,
                wire_attempts=1,
                provider_items=2,
                accepted_items=2,
            ),
        )


@mark_synthetic_capability
def _fake_collector(_snapshot: SourceSnapshot, context: CollectorContext) -> FakeBroadCollector:
    assert context.transport is not None
    return FakeBroadCollector(context.transport)


def _config(root: Path, plan_sha256: str) -> AcquisitionScaffoldConfig:
    return AcquisitionScaffoldConfig(
        evidence_root=root,
        operation_id="op-gate-d",
        provenance_sha256="a" * 64,
        preregistration_sha256="b" * 64,
        source_plan_sha256=plan_sha256,
        budget_id="budget-gate-d",
        namespace="f10-1f-20260825-a7f3c9",
    )


@pytest.mark.asyncio
async def test_gate_d_mixed_board_enters_pool_without_product_persistence(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    delegate = SyntheticTransport()
    budget = CollectionRunBudget(maximum=1)
    journal = AcquisitionJournal(operation_id="op-gate-d", root=root)
    source_plan = build_source_plan(
        namespace="f10-1f-20260825-a7f3c9",
        root=str(root),
        per_board_cap=4,
        per_company_cap=2,
        budget=SourcePlanBudget("budget-gate-d", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-gate-d",
        lineage_id="lineage-gate-d",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )

    def before_after() -> tuple[dict[str, int], dict[str, int]]:
        state = {"sources": 1, "jobs": 1, "runs": 0}
        return state, state.copy()

    result = await run_gate_d_broad_acquisition(
        config=_config(root, source_plan.source_plan_sha256),
        source_plan=source_plan,
        delegate=delegate,
        budget=budget,
        evidence_root=root,
        journal=journal,
        before_after=before_after,
        collector_factory=_fake_collector,
        test_only_adapter=synthetic_test_adapter(),
    )

    assert delegate.calls == 1
    assert result.source_count == 1
    assert len(result.observations) == 2
    assert_mixed_board_sealed(
        observations=result.observations,
        relevant_predicate=lambda item: "Engineer" in item.title,
    )
    assert result.manifest.observed == result.manifest.new_to_pool == 2
    assert result.manifest.duplicate == result.manifest.stale == 0
    assert result.manifest.invalid == result.manifest.conflict == 0
    assert result.manifest.durable_intents == 1
    assert result.manifest.durable_intents == result.manifest.known_terminal_outcomes
    assert result.manifest.durable_intents == result.manifest.delegate_entries
    assert result.manifest.durable_intents == result.manifest.budget_debits
    assert result.manifest.durable_intents == result.manifest.collector_wire_attempts
    assert result.manifest.durable_intents == result.manifest.budget_consumed
    assert result.manifest.durable_intents == result.manifest.checkpoint_wire_attempts
    assert result.manifest.pending_or_indeterminate == 0
    assert result.sealed_pool_path is not None
    assert result.sealed_manifest_path is not None
    assert result.sealed_pool_path.is_file()
    assert result.sealed_manifest_path.is_file()
    assert not (root / "sources").exists()
    assert not (root / "jobs").exists()


@pytest.mark.asyncio
async def test_gate_d_pending_journal_blocks_replay_without_delegate_call(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    journal = AcquisitionJournal(operation_id="op-gate-d", root=root)
    source_id = f"ephemeral:{hashlib.sha256(b'greenhouse:acme').hexdigest()[:32]}"
    journal.record_intent(
        source_id=source_id,
        ordinal=1,
        destination_fingerprint="a" * 16,
        budget_ordinal=1,
    )
    source_plan = build_source_plan(
        namespace="f10-1f-20260825-a7f3c9",
        root=str(root),
        per_board_cap=4,
        per_company_cap=2,
        budget=SourcePlanBudget("budget-gate-d", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-gate-d",
        lineage_id="lineage-gate-d",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )
    delegate = SyntheticTransport()
    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=_config(root, source_plan.source_plan_sha256),
            source_plan=source_plan,
            delegate=delegate,
            budget=CollectionRunBudget(maximum=1),
            journal=journal,
            checkpoints={source_id: SourceCheckpoint(source_id, 1, "d" * 64)},
            collector_factory=_fake_collector,
            test_only_adapter=synthetic_test_adapter(),
        )
    assert exc.value.code == "acquisition_source_blocked_pending"
    assert delegate.calls == 0


@pytest.mark.asyncio
async def test_gate_d_legacy_network_requires_explicit_boundary(tmp_path: Path) -> None:
    delegate = SyntheticTransport()
    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=_config(tmp_path / "evidence", "c" * 64),
            source_plan=object(),  # type: ignore[arg-type]
            delegate=delegate,
        )
    assert exc.value.code == "acquisition_execution_authorization_required"
    assert delegate.calls == 0


@pytest.mark.asyncio
async def test_gate_d_stale_plan_hash_blocks_before_collector_invocation(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    plan = build_source_plan(
        namespace="f10-1f-20260825-a7f3c9",
        root=str(root),
        per_board_cap=4,
        per_company_cap=2,
        budget=SourcePlanBudget("budget-gate-d", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-gate-d",
        lineage_id="lineage-gate-d",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )
    delegate = MockTransport()
    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=replace(_config(root, plan.source_plan_sha256), source_plan_sha256="d" * 64),
            source_plan=plan,
            delegate=delegate,  # type: ignore[arg-type]
            budget=CollectionRunBudget(maximum=1),
            test_only_adapter=synthetic_test_adapter(),
        )
    assert exc.value.code == "acquisition_source_plan_hash_mismatch"
    assert delegate.calls == 0


@pytest.mark.asyncio
async def test_gate_d_rejects_arbitrary_httpx_transport_without_invoking_it(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    plan = build_source_plan(
        namespace="f10-1f-20260825-a7f3c9",
        root=str(root),
        per_board_cap=4,
        per_company_cap=2,
        budget=SourcePlanBudget("budget-gate-d", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-gate-d",
        lineage_id="lineage-gate-d",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )
    delegate = MockTransport()
    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=_config(root, plan.source_plan_sha256),
            source_plan=plan,
            delegate=delegate,  # type: ignore[arg-type]
            budget=CollectionRunBudget(maximum=1),
            collector_factory=_fake_collector,
            test_only_adapter=synthetic_test_adapter(),
        )
    assert exc.value.code == "acquisition_production_transport_rejected"
    assert delegate.calls == 0


@pytest.mark.asyncio
async def test_gate_d_rejects_caller_root_override_before_factory(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    override = tmp_path / "override"
    plan = build_source_plan(
        namespace="f10-1f-20260825-a7f3c9",
        root=str(root),
        per_board_cap=4,
        per_company_cap=2,
        budget=SourcePlanBudget("budget-gate-d", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-gate-d",
        lineage_id="lineage-gate-d",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )
    factory_calls = 0

    @mark_synthetic_capability
    def factory(_snapshot: SourceSnapshot, _context: CollectorContext) -> FakeBroadCollector:
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("factory must not run")

    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=_config(root, plan.source_plan_sha256),
            source_plan=plan,
            delegate=SyntheticTransport(),
            budget=CollectionRunBudget(maximum=1),
            evidence_root=override,
            collector_factory=factory,
            test_only_adapter=synthetic_test_adapter(),
        )
    assert exc.value.code == "acquisition_source_plan_root_mismatch"
    assert factory_calls == 0


@pytest.mark.asyncio
async def test_gate_d_rejects_unmarked_provider_factory_before_provider_call(
    tmp_path: Path,
) -> None:
    root = tmp_path / "evidence"
    plan = build_source_plan(
        namespace="f10-1f-20260825-a7f3c9",
        root=str(root),
        per_board_cap=4,
        per_company_cap=2,
        budget=SourcePlanBudget("budget-gate-d", 1),
        seed=SeedInputs("a" * 64, "b" * 64),
        operation_id="op-gate-d",
        lineage_id="lineage-gate-d",
        source_configs=(
            {
                "family": "greenhouse",
                "source_key": "greenhouse:acme",
                "configuration_version": 1,
                "configuration": {"board_token": "acme"},
            },
        ),
    )
    provider_calls = 0

    def provider(_snapshot: SourceSnapshot, _context: CollectorContext) -> object:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("provider must not run")

    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=_config(root, plan.source_plan_sha256),
            source_plan=plan,
            delegate=SyntheticTransport(),
            budget=CollectionRunBudget(maximum=1),
            collector_factory=provider,  # type: ignore[arg-type]
            test_only_adapter=synthetic_test_adapter(),
        )
    assert exc.value.code == "acquisition_synthetic_collector_required"
    assert provider_calls == 0
