"""Offline Gate D integration: mixed-board broad pool and reconciliation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.policy import CollectionRunBudget
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.collectors.registry import CollectorContext
from role_radar.domain.dto import RawJob
from role_radar.evaluation.controlled_acquisition.protocols import PLAN_VERSION_V2
from role_radar.evaluation.controlled_acquisition.source_plan import SourcePlan
from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    AcquisitionError,
    AcquisitionScaffoldConfig,
    SourceCheckpoint,
    assert_mixed_board_sealed,
    run_gate_d_broad_acquisition,
)
from role_radar.evaluation.profile_relevant_acquisition.contracts import (
    synthetic_test_adapter,
)
from role_radar.evaluation.profile_relevant_acquisition.journal import AcquisitionJournal


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, request=request, content=b'{"jobs":[]}')


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


def _fake_collector(_snapshot: SourceSnapshot, context: CollectorContext) -> FakeBroadCollector:
    assert context.transport is not None
    return FakeBroadCollector(context.transport)


def _config(root: Path) -> AcquisitionScaffoldConfig:
    return AcquisitionScaffoldConfig(
        evidence_root=root,
        operation_id="op-gate-d",
        provenance_sha256="a" * 64,
        preregistration_sha256="b" * 64,
        source_plan_sha256="c" * 64,
        budget_id="budget-gate-d",
        namespace="f10-1f-20260825-a7f3c9",
    )


@pytest.mark.asyncio
async def test_gate_d_mixed_board_enters_pool_without_product_persistence(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    delegate = MockTransport()
    budget = CollectionRunBudget(maximum=1)
    journal = AcquisitionJournal(operation_id="op-gate-d", root=root)
    source_plan = SourcePlan(
        plan_version=PLAN_VERSION_V2,
        lookback_days=1,
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
        config=_config(root),
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
    source_plan = SourcePlan(
        plan_version=PLAN_VERSION_V2,
        lookback_days=1,
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
            config=_config(root),
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
    delegate = MockTransport()
    with pytest.raises(AcquisitionError) as exc:
        await run_gate_d_broad_acquisition(
            config=_config(tmp_path / "evidence"),
            source_plan=object(),
            delegate=delegate,
        )
    assert exc.value.code == "acquisition_execution_authorization_required"
    assert delegate.calls == 0
