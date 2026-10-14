"""Offline report-only integration boundary; no provider or DB side effect."""

from __future__ import annotations

from argparse import Namespace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from role_radar.continuous_acquisition.discovery_artifacts_v2 import ReportOnlyVerifiedSourceV1
from role_radar.continuous_acquisition.discovery_budget_v2 import DiscoveryBudgetV2
from role_radar.continuous_acquisition.providers import SearchAuthorizationCapability
from role_radar.continuous_acquisition.report_only_v2 import (
    prepare_report_only_operation,
    verify_report_only_authorization,
)
from role_radar.continuous_acquisition.runtime_discovery_v2 import (
    build_discovery_plan,
    build_search_runtime,
    execute_report_only_runtime,
    run_continuous_discovery_v2,
)
from role_radar.db.base import Base
from role_radar.db.models import (
    AcquisitionBudgetPeriod,
    AcquisitionReservation,
    Job,
    ProviderCallLedger,
    Source,
)
from role_radar.discovery.contracts import ProviderTier, SearchResponse, TransientSearchHit
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1
from role_radar.domain.enums import JobStatus, SourceType
from role_radar.domain.profile import CandidateProfileV1, canonical_profile_sha256
from role_radar.repositories.acquisition import (
    AcquisitionRepository,
    DiscoveryQuotaContextV2,
)


class _Quota:
    enabled = True
    units_limit = 4


class _Config:
    config_version = "config-v1"
    brave_free = _Quota()
    tavily_free = _Quota()


def _capability(
    *,
    operation_id: str,
    operation_sha256: str,
    plan_sha256: str,
    expires_at_utc: datetime,
    authorization_sha256: str,
) -> SearchAuthorizationCapability:
    """Construct the injected test-only capability without a production issuer."""

    capability = object.__new__(SearchAuthorizationCapability)
    object.__setattr__(capability, "operation_id", operation_id)
    object.__setattr__(capability, "operation_sha256", operation_sha256)
    object.__setattr__(capability, "plan_sha256", plan_sha256)
    object.__setattr__(capability, "expires_at_utc", expires_at_utc)
    object.__setattr__(capability, "allowed_providers", ("brave", "tavily"))
    object.__setattr__(capability, "authorization_sha256", authorization_sha256)
    return capability


def _profile() -> CandidateProfileV1:
    return CandidateProfileV1.model_validate(
        {
            "title": "backend engineer",
            "years_of_experience": 5,
            "target_roles": ["backend"],
            "target_titles": ["Backend Engineer"],
            "core_skills": ["python"],
            "secondary_skills": [],
            "regions": ["remote"],
            "remote_only": True,
            "employment_preferences": ["full_time"],
            "languages": {"en": "professional"},
            "excluded_roles": [],
            "excluded_technologies": [],
            "hard_constraints": {
                "available_work_authorizations": [],
                "unavailable_work_authorizations": [],
                "allowed_employment_types": [],
            },
            "soft_preferences": {"preferred_industries": []},
        }
    )


def _policy(profile: CandidateProfileV1) -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_version": "gate-a-v1",
        "profile_binding": {
            "profile_id": "00000000-0000-0000-0000-000000000001",
            "row_version": 1,
            "schema_version": 1,
            "canonical_profile_sha256": canonical_profile_sha256(profile.model_dump(mode="json")),
        },
        "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
        "groups": {"backend": ["Backend Engineer"]},
        "target_roles": {"backend": {"primary_groups": ["backend"]}},
        "target_titles": {"backend engineer": {"primary_groups": ["backend"]}},
    }


def test_report_only_requires_explicit_gate_c_packet_before_execution() -> None:
    result = run_continuous_discovery_v2(
        Namespace(continuous_discovery_v2_command="run-report-only")
    )
    assert result.exit_code == 2
    assert result.payload["code"] == "discovery_v2_authorization_required"

def test_offline_prepare_publishes_only_plan_and_operation(tmp_path: Path) -> None:
    profile = _profile()
    result = run_continuous_discovery_v2(
        Namespace(
            continuous_discovery_v2_command="prepare-report-only",
            operation_id="00000000-0000-0000-0000-000000000002",
        ),
        policy=_policy(profile),
        profile=profile,
        config=_Config(),
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
    )

    assert result.exit_code == 0
    assert result.payload["schema_version"] == "report-only-operation-v1"
    assert list((tmp_path / "plans").glob("*.json"))
    operations = list((tmp_path / "report-only" / "operations").rglob("operation-v1.json"))
    assert len(operations) == 1
    started = (
        tmp_path
        / "report-only"
        / "operations"
        / "00000000-0000-0000-0000-000000000002"
        / "started-v1.json"
    )
    assert not started.exists()


class _Publication:
    reservation_id = "reservation-1"


class _QuotaAdapter:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.finalized: list[str] = []
        self.commits = 0

    def reserve_and_start_v2(self, *, operation_key: str, **_kwargs: object) -> _Publication:
        self.started.append(operation_key)
        return _Publication()

    def finalize_v2(self, *, reservation_id: str, **_kwargs: object) -> object:
        self.finalized.append(reservation_id)
        return object()

    def revalidate_context_v2(
        self, *, context: object, **_kwargs: object
    ) -> DiscoveryQuotaContextV2:
        return cast(DiscoveryQuotaContextV2, context)

    def commit_v2(self) -> None:
        self.commits += 1


class _EmptyProvider:
    def __init__(self, provider: Literal["brave", "tavily"] = "brave") -> None:
        self.provider: str = provider
        self.calls = 0

    async def search(self, _request: object) -> SearchResponse:
        self.calls += 1
        return SearchResponse(
            provider=cast(Literal["brave", "tavily"], self.provider),
            tier=ProviderTier.FREE,
            status="empty",
        )


class _FailedProvider:
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


class _ExplodingProvider:
    provider = "brave"

    async def search(self, _request: object) -> SearchResponse:
        raise OSError("transport unavailable")


class _BoardProvider:
    provider = "brave"

    async def search(self, _request: object) -> SearchResponse:
        return SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="succeeded",
            hits=(TransientSearchHit(url="https://boards.greenhouse.io/acme", rank=1),),
            result_count=1,
            known_count=1,
        )


class _ManyBoardsProvider:
    provider = "brave"

    def __init__(self) -> None:
        self.calls = 0

    async def search(self, _request: object) -> SearchResponse:
        batch = self.calls
        self.calls += 1
        hits = tuple(
            TransientSearchHit(url=f"https://boards.greenhouse.io/board{batch}-{index}", rank=index)
            for index in range(1, 11)
        )
        return SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="succeeded",
            hits=hits,
            result_count=10,
            known_count=10,
        )


def _table_counts(session: Session) -> dict[str, int]:
    return {
        table.name: int(session.scalar(select(func.count()).select_from(table)) or 0)
        for table in Base.metadata.sorted_tables
    }


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@pytest.mark.asyncio
async def test_injected_report_only_runtime_publishes_marker_terminal_and_replays(
    tmp_path: Path,
) -> None:
    profile = _profile()
    policy = _policy(profile)
    plan = build_discovery_plan(policy=policy, profile=profile)
    operation = prepare_report_only_operation(
        plan,
        _Config(),
        operation_id="00000000-0000-0000-0000-000000000003",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
        artifact_root=tmp_path,
    )
    evidence = verify_report_only_authorization(
        operation, now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    provider = _EmptyProvider()
    quota = _QuotaAdapter()
    runtime = build_search_runtime(
        _Config(),
        plan,
        _capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=plan.plan_sha256,
            expires_at_utc=operation.authorization_expires_at_utc,
            authorization_sha256=evidence.authorization_sha256,
        ),
        DiscoveryBudgetV2(operation.operation.budgets),
        quota,
    )
    runtime.brave = provider
    runtime.tavily = None

    report = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, 0, 1, tzinfo=UTC),
    )

    assert report.state == "completed_empty"
    assert len(report.requests) == 4
    assert len(quota.started) == 4
    assert len(quota.finalized) == 4
    assert quota.commits == 8
    assert provider.calls == 4
    assert (
        tmp_path / "report-only" / "operations" / operation.operation_id / "started-v1.json"
    ).exists()
    assert (
        tmp_path / "report-only" / "operations" / operation.operation_id / "terminal-report-v1.json"
    ).exists()

    replay = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 25, 12, tzinfo=UTC),
    )
    assert replay.report_sha256 == report.report_sha256
    assert provider.calls == 4


@pytest.mark.asyncio
async def test_injected_report_only_runtime_publishes_indeterminate_terminal(
    tmp_path: Path,
) -> None:
    profile = _profile()
    plan = build_discovery_plan(policy=_policy(profile), profile=profile)
    operation = prepare_report_only_operation(
        plan,
        _Config(),
        operation_id="00000000-0000-0000-0000-000000000004",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
        artifact_root=tmp_path,
    )
    evidence = verify_report_only_authorization(
        operation, now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    quota = _QuotaAdapter()
    runtime = build_search_runtime(
        _Config(),
        plan,
        _capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=plan.plan_sha256,
            expires_at_utc=operation.authorization_expires_at_utc,
            authorization_sha256=evidence.authorization_sha256,
        ),
        DiscoveryBudgetV2(operation.operation.budgets),
        quota,
    )
    runtime.brave = _ExplodingProvider()
    tavily = _EmptyProvider("tavily")
    runtime.tavily = tavily

    report = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, 0, 1, tzinfo=UTC),
    )

    assert report.state == "indeterminate"
    assert report.terminal_code == "transmission_indeterminate"
    assert len(quota.finalized) == 1
    assert quota.commits == 2
    assert tavily.calls == 0


@pytest.mark.asyncio
async def test_report_only_runtime_falls_back_after_proven_search_failure(
    tmp_path: Path,
) -> None:
    profile = _profile()
    plan = build_discovery_plan(policy=_policy(profile), profile=profile)
    operation = prepare_report_only_operation(
        plan,
        _Config(),
        operation_id="00000000-0000-0000-0000-000000000007",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
        artifact_root=tmp_path,
    )
    evidence = verify_report_only_authorization(
        operation, now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    quota = _QuotaAdapter()
    runtime = build_search_runtime(
        _Config(),
        plan,
        _capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=plan.plan_sha256,
            expires_at_utc=operation.authorization_expires_at_utc,
            authorization_sha256=evidence.authorization_sha256,
        ),
        DiscoveryBudgetV2(operation.operation.budgets),
        quota,
    )
    brave = _FailedProvider()
    tavily = _EmptyProvider("tavily")
    runtime.brave = brave
    runtime.tavily = tavily

    report = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, 0, 1, tzinfo=UTC),
    )

    assert report.state == "completed_empty"
    assert len(report.requests) == 8
    assert brave.calls == tavily.calls == 4


@pytest.mark.asyncio
async def test_report_only_runtime_commits_exact_quota_ledger_boundaries(
    tmp_path: Path, db_session: Session
) -> None:
    source = Source(
        type=SourceType.GREENHOUSE,
        name="existing source",
        source_key="greenhouse:existing",
        configuration={"board_token": "existing"},
    )
    job = Job(title="existing job", company="existing company", status=JobStatus.NEW)
    db_session.add_all([source, job])
    db_session.flush()
    before_counts = _table_counts(db_session)
    before_source = (source.name, source.source_key, source.revision, source.enabled)
    before_job = (job.title, job.company, job.status, _aware(job.updated_at))

    profile = _profile()
    plan = build_discovery_plan(policy=_policy(profile), profile=profile)
    operation = prepare_report_only_operation(
        plan,
        _Config(),
        operation_id="00000000-0000-0000-0000-000000000005",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
        artifact_root=tmp_path,
    )
    evidence = verify_report_only_authorization(
        operation, now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    runtime = build_search_runtime(
        _Config(),
        plan,
        _capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=plan.plan_sha256,
            expires_at_utc=operation.authorization_expires_at_utc,
            authorization_sha256=evidence.authorization_sha256,
        ),
        DiscoveryBudgetV2(operation.operation.budgets),
        AcquisitionRepository(db_session),
    )
    provider = _EmptyProvider()
    runtime.brave = provider
    runtime.tavily = None

    report = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, 0, 1, tzinfo=UTC),
    )

    assert report.state == "completed_empty"
    period = db_session.scalar(select(AcquisitionBudgetPeriod))
    reservations = list(db_session.scalars(select(AcquisitionReservation)))
    ledgers = list(db_session.scalars(select(ProviderCallLedger)))
    assert period is not None
    assert (period.units_reserved, period.units_used) == (0, 4)
    assert len(reservations) == len(ledgers) == 4
    assert all(item.status == "spent" for item in reservations)
    assert all(item.status == "empty" for item in ledgers)
    after_counts = _table_counts(db_session)
    changed_tables = {name for name, count in after_counts.items() if count != before_counts[name]}
    assert changed_tables == {
        "acquisition_budget_periods",
        "acquisition_reservations",
        "provider_call_ledger",
    }
    assert (source.name, source.source_key, source.revision, source.enabled) == before_source
    assert (job.title, job.company, job.status, _aware(job.updated_at)) == before_job


@pytest.mark.asyncio
async def test_report_only_runtime_verifies_one_official_board_without_registration(
    tmp_path: Path,
) -> None:
    profile = _profile()
    plan = build_discovery_plan(policy=_policy(profile), profile=profile)
    operation = prepare_report_only_operation(
        plan,
        _Config(),
        operation_id="00000000-0000-0000-0000-000000000006",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
        artifact_root=tmp_path,
    )
    evidence = verify_report_only_authorization(
        operation, now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    quota = _QuotaAdapter()
    runtime = build_search_runtime(
        _Config(),
        plan,
        _capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=plan.plan_sha256,
            expires_at_utc=operation.authorization_expires_at_utc,
            authorization_sha256=evidence.authorization_sha256,
        ),
        DiscoveryBudgetV2(operation.operation.budgets),
        quota,
    )
    runtime.brave = _BoardProvider()
    runtime.tavily = None

    async def verify(_candidate: object) -> ReportOnlyVerifiedSourceV1:
        return ReportOnlyVerifiedSourceV1(
            source_type="greenhouse",
            source_key="greenhouse:acme",
            configuration={"board_token": "acme"},
            configuration_sha256=sha256(b'{"board_token":"acme"}').hexdigest(),
            postings_count=2,
            board_candidate_ordinal=1,
            request_identity_sha256="b" * 64,
        )

    report = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        official_verifier=verify,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, 0, 1, tzinfo=UTC),
    )

    assert report.state == "completed"
    assert len(report.verified_sources) == 1
    assert report.counts["board_verifications_attempted"] == 1
    assert report.counts["boards_verified"] == 1


@pytest.mark.asyncio
async def test_report_only_runtime_marks_post_dedup_candidate_truncation(
    tmp_path: Path,
) -> None:
    profile = _profile()
    plan = build_discovery_plan(policy=_policy(profile), profile=profile)
    operation = prepare_report_only_operation(
        plan,
        _Config(),
        operation_id="00000000-0000-0000-0000-000000000008",
        clock=datetime(2026, 8, 24, 12, tzinfo=UTC),
        nonce_source=lambda: b"n" * 32,
        artifact_root=tmp_path,
    )
    evidence = verify_report_only_authorization(
        operation, now=datetime(2026, 8, 24, 12, tzinfo=UTC)
    )
    runtime = build_search_runtime(
        _Config(),
        plan,
        _capability(
            operation_id=operation.operation_id,
            operation_sha256=operation.operation_sha256,
            plan_sha256=plan.plan_sha256,
            expires_at_utc=operation.authorization_expires_at_utc,
            authorization_sha256=evidence.authorization_sha256,
        ),
        DiscoveryBudgetV2(operation.operation.budgets),
        _QuotaAdapter(),
    )
    runtime.brave = _ManyBoardsProvider()
    runtime.tavily = None

    report = await execute_report_only_runtime(
        operation,
        evidence,
        _Config(),
        search_runtime=runtime,
        artifact_root=tmp_path,
        clock=datetime(2026, 8, 24, 12, 0, 1, tzinfo=UTC),
    )

    assert report.state == "completed_partial"
    assert report.terminal_code == "unique_board_candidates_exhausted"
    assert report.truncation["unique_board_candidates"] is True
    assert report.counts["unique_board_candidates_seen"] == 40
    assert report.counts["unique_board_candidates_retained"] == 10
