"""Offline tests for the continuous-acquisition provider wiring."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal, cast

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.registry import CollectorConfigurationError
from role_radar.continuous_acquisition.acquisition import AcquisitionService
from role_radar.continuous_acquisition.contracts import (
    AcquisitionRunState,
    DiscoveryCandidate,
    OperationState,
    RequestBudget,
    SourceSnapshot,
)
from role_radar.continuous_acquisition.providers import (
    BoundedCollectorProvider,
    BoundedSearchRuntime,
    OfficialATSVerifier,
    collector_snapshot,
)
from role_radar.db.models import Job, Source
from role_radar.discovery.contracts import (
    ProviderTier,
    SearchRequest,
    SearchResponse,
    TransientSearchHit,
)

AS_OF = datetime(2026, 8, 13, 12, tzinfo=UTC)


@pytest.mark.parametrize(
    ("source_type", "configuration", "source_key", "expected"),
    [
        (
            "greenhouse",
            {"board_token": " ACME ", "company": "Acme"},
            "greenhouse:acme",
            {"board_token": "acme", "company": "Acme"},
        ),
        (
            "lever",
            {"site": " ACME ", "region": "EU", "company": "Acme"},
            "lever:eu:acme",
            {"site": "acme", "region": "eu", "company": "Acme"},
        ),
    ],
)
def test_collector_snapshot_normalizes_v1_without_copying_revision(
    source_type: str,
    configuration: dict[str, str],
    source_key: str,
    expected: dict[str, str],
) -> None:
    normalized = collector_snapshot(
        SourceSnapshot(
            "source-1",
            source_key,
            source_type,
            "Acme",
            configuration,
            revision=9,
        )
    )

    assert normalized.configuration_version == 1
    assert dict(normalized.configuration) == expected
    assert normalized.source_key == source_key


@pytest.mark.parametrize(
    "snapshot",
    [
        SourceSnapshot(
            "source-1",
            "greenhouse:acme",
            "greenhouse",
            "Acme",
            {"board_token": "acme", "origin": "https://evil.test"},
        ),
        SourceSnapshot(
            "source-1", "greenhouse:wrong", "greenhouse", "Acme", {"board_token": "acme"}
        ),
        SourceSnapshot("source-1", "other:acme", "other", "Acme", {"board_token": "acme"}),
    ],
)
def test_collector_snapshot_rejects_invalid_configuration_or_origin(
    snapshot: SourceSnapshot,
) -> None:
    with pytest.raises(CollectorConfigurationError):
        collector_snapshot(snapshot)

    with pytest.raises(ValueError, match="revision"):
        collector_snapshot(
            SourceSnapshot(
                "source-1",
                "greenhouse:acme",
                "greenhouse",
                "Acme",
                {"board_token": "acme"},
                revision=0,
            )
        )


class _FakeCollector:
    def __init__(self, result: CollectionSuccess) -> None:
        self.result = result
        self.calls: list[tuple[object, object]] = []

    async def collect(self, snapshot: object, runtime: object) -> CollectionSuccess:
        self.calls.append((snapshot, runtime))
        return self.result


@pytest.mark.asyncio
async def test_bounded_collector_provider_uses_fake_collector_and_returns_empty_without_downstream() -> (  # noqa: E501
    None
):
    transport = httpx.MockTransport(
        lambda _request: (_ for _ in ()).throw(AssertionError("network must not be used"))
    )
    fake = _FakeCollector(CollectionSuccess(status="ok", jobs=(), metrics=CollectionMetrics()))
    factory_calls: list[tuple[object, object]] = []

    def factory(snapshot: object, context: object) -> _FakeCollector:
        factory_calls.append((snapshot, context))
        return fake

    provider = BoundedCollectorProvider(transport=transport, collector_factory=factory)
    outcome = await provider(
        SourceSnapshot("source-1", "greenhouse:acme", "greenhouse", "Acme", {"board_token": "acme"})
    )

    assert isinstance(outcome, CollectionSuccess)
    assert outcome.jobs == ()
    assert len(factory_calls) == 1
    assert len(fake.calls) == 1


@pytest.mark.parametrize(
    ("source_type", "configuration", "expected_url", "payload"),
    [
        (
            "greenhouse",
            {"board_token": "acme"},
            "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
            {"jobs": []},
        ),
        (
            "lever",
            {"site": "acme", "region": "global"},
            "https://api.lever.co/v0/postings/acme?mode=json&limit=100&skip=0",
            [],
        ),
        (
            "lever",
            {"site": "acme", "region": "eu"},
            "https://api.eu.lever.co/v0/postings/acme?mode=json&limit=100&skip=0",
            [],
        ),
    ],
)
@pytest.mark.asyncio
async def test_bounded_collector_provider_uses_exact_official_ats_origin_and_path(
    source_type: str,
    configuration: dict[str, str],
    expected_url: str,
    payload: object,
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=payload)

    source_key = (
        "greenhouse:acme"
        if source_type == "greenhouse"
        else f"lever:{configuration['region']}:acme"
    )
    provider = BoundedCollectorProvider(transport=httpx.MockTransport(handler))
    outcome = await provider(
        SourceSnapshot("source-1", source_key, source_type, "Acme", configuration)
    )

    assert isinstance(outcome, CollectionSuccess)
    assert outcome.jobs == ()
    assert seen == [expected_url]


class _SearchStub:
    provider: str

    def __init__(
        self,
        provider: Literal["brave", "tavily"],
        status: Literal["succeeded", "empty", "failed", "malformed", "indeterminate"],
    ) -> None:
        self.provider = provider
        self.status = status
        self.requests: list[SearchRequest] = []

    async def search(self, request: SearchRequest) -> SearchResponse:
        self.requests.append(request)
        hits: tuple[TransientSearchHit, ...] = ()
        if self.status == "succeeded":
            call_number = len(self.requests)
            hits = tuple(
                TransientSearchHit(
                    url=(
                        f"https://evil.test/{call_number}-{index}"
                        if call_number == 1 and index == 1
                        else f"https://boards.greenhouse.io/{self.provider}-{call_number}-{index}"
                    ),
                    rank=index,
                )
                for index in range(1, 11)
            )
        return SearchResponse(
            provider=cast(Literal["brave", "tavily"], self.provider),
            tier=ProviderTier.FREE,
            status=self.status,
            hits=hits,
            result_count=len(hits),
            error_code="upstream" if self.status == "failed" else None,
        )


@pytest.mark.asyncio
async def test_bounded_search_runtime_caps_brave_and_tavily_and_total_hits() -> None:
    brave = _SearchStub("brave", "failed")
    tavily = _SearchStub("tavily", "succeeded")

    candidates = await BoundedSearchRuntime(brave=brave, tavily=tavily).run()

    assert len(brave.requests) == 4
    assert len(tavily.requests) == 4
    assert all(request.max_results == 10 for request in (*brave.requests, *tavily.requests))
    assert all(request.cycle_query_count == 4 for request in (*brave.requests, *tavily.requests))
    assert len(candidates) == 10
    assert all(
        candidate.url.startswith("https://boards.greenhouse.io/") for candidate in candidates
    )
    assert all(not candidate.url.startswith("https://evil.test/") for candidate in candidates)


@pytest.mark.parametrize(
    ("candidate_url", "expected_key", "expected_configuration", "expected_url"),
    [
        (
            "https://boards.greenhouse.io/acme",
            "greenhouse:acme",
            {"board_token": "acme"},
            "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
        ),
        (
            "https://jobs.eu.lever.co/acme",
            "lever:eu:acme",
            {"site": "acme", "region": "eu"},
            "https://api.eu.lever.co/v0/postings/acme?mode=json&limit=100&skip=0",
        ),
    ],
)
@pytest.mark.asyncio
async def test_official_ats_verifier_accepts_empty_board_without_persisting_rows(
    db_session: Session,
    candidate_url: str,
    expected_key: str,
    expected_configuration: dict[str, str],
    expected_url: str,
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        payload: object = {"jobs": []} if "greenhouse" in expected_url else []
        return httpx.Response(200, json=payload)

    before_jobs = db_session.scalar(select(func.count()).select_from(Job))
    before_sources = db_session.scalar(select(func.count()).select_from(Source))
    verifier = OfficialATSVerifier(BoundedCollectorProvider(transport=httpx.MockTransport(handler)))

    verified = await verifier(DiscoveryCandidate(candidate_url, "tavily", 1))

    assert verified is not None
    assert verified.source_key == expected_key
    assert dict(verified.configuration) == expected_configuration
    assert verified.postings == 0
    assert seen == [expected_url]
    assert db_session.scalar(select(func.count()).select_from(Job)) == before_jobs
    assert db_session.scalar(select(func.count()).select_from(Source)) == before_sources


class _FakeSession:
    def __init__(self) -> None:
        self.commits = 0

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        return None


class _FakeRunRepository:
    def __init__(self) -> None:
        self.session = _FakeSession()
        self.fenced: list[str] = []
        self.finalized_operations: list[str] = []
        self.finalized_run: dict[str, object] | None = None

    def claim_acquisition(self, **_kwargs: object) -> object:
        return type("Run", (), {"id": "run-1", "state": "running", "fencing_generation": 1})()

    def fence(self, run_id: str, *, owner: str, generation: int) -> None:
        self.fenced.append(f"{run_id}:{owner}:{generation}")

    def create_operation(self, *_args: object, **_kwargs: object) -> object:
        return type("Operation", (), {"id": f"operation-{len(self.finalized_operations) + 1}"})()

    def finalize_operation(self, operation_id: str, **_kwargs: object) -> None:
        self.finalized_operations.append(operation_id)

    def finalize_run(self, run_id: str, **values: object) -> None:
        self.finalized_run = {"run_id": run_id, **values}


def test_acquisition_service_runs_async_provider_sequentially_and_honors_budget() -> None:
    snapshots = (
        SourceSnapshot(
            "source-a", "greenhouse:acme", "greenhouse", "Acme", {"board_token": "acme"}
        ),
        SourceSnapshot(
            "source-b", "greenhouse:beta", "greenhouse", "Beta", {"board_token": "beta"}
        ),
    )
    calls: list[str] = []
    active = 0

    async def provider(source: SourceSnapshot) -> CollectionSuccess:
        nonlocal active
        active += 1
        assert active == 1
        calls.append(source.source_id)
        await asyncio.sleep(0)
        active -= 1
        return CollectionSuccess(status="ok", jobs=(), metrics=CollectionMetrics())

    repository = _FakeRunRepository()
    service = AcquisitionService(
        run_repository=repository,  # type: ignore[arg-type]
        snapshots=snapshots,
        collectors={"greenhouse": provider},
        as_of_utc=AS_OF,
        owner="test-worker",
        budget=RequestBudget(maximum=1),
    )

    result = service.run(slot_key="wiring-budget")

    assert len(calls) == 1
    assert result.state is AcquisitionRunState.COMPLETED_PARTIAL
    assert result.new_jobs == 0
    assert result.counters.observed == 0
    assert result.outcomes[-1].state is OperationState.TRUNCATED
    assert result.outcomes[-1].error_code == "budget_exhausted"
    assert repository.finalized_run is not None
    assert repository.finalized_run["reserved_requests"] == 1
    assert repository.finalized_run["attempted_requests"] == 1
    assert repository.finalized_run["completed_requests"] == 1
