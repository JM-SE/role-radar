from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from role_radar.broker.fake import FakeLLMProvider
from role_radar.collectors.outcomes import CollectionMetrics, CollectionSuccess
from role_radar.collectors.protocols import CollectorRuntime, SourceSnapshot
from role_radar.config import Settings
from role_radar.db.base import Base
from role_radar.db.models import (
    DiscoveryCycle,
    JobSearchRun,
    NotificationBatch,
    NotificationItem,
    RunJob,
    Source,
    SourceActivationMember,
)
from role_radar.db.session import get_session_factory
from role_radar.discovery.contracts import ProviderTier, SearchResponse, TransientSearchHit
from role_radar.discovery.policy import DiscoveryPhraseGrammarV1, DiscoveryPolicyV1
from role_radar.domain.dto import RawJob
from role_radar.domain.enums import (
    DiscoveryCycleStatus,
    JobSearchRunStatus,
    NotificationBatchStatus,
    NotificationMode,
    SourceType,
)
from role_radar.domain.profile import canonical_profile_sha256
from role_radar.notifications.contracts import Accepted, TelegramSendRequest
from role_radar.repositories.profiles import ProfileRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.notification_service import NotificationService
from role_radar.services.source_activation import SourceActivationCampaignService
from role_radar.worker.pipeline import Pipeline


class AcceptedGateway:
    def __init__(self) -> None:
        self.requests: list[TelegramSendRequest] = []

    async def send_message(self, request: TelegramSendRequest) -> Accepted:
        self.requests.append(request)
        return Accepted(message_id=len(self.requests))


class SearchProvider:
    def __init__(self) -> None:
        self.requests = []

    async def search(self, request) -> SearchResponse:
        self.requests.append(request)
        return SearchResponse(
            provider="brave",
            tier=ProviderTier.FREE,
            status="succeeded",
            hits=(
                TransientSearchHit(
                    url="https://boards.greenhouse.io/newco",
                    rank=1,
                ),
            ),
            result_count=1,
        )


def test_campaign_source_job_reaches_simulated_outbox(tmp_path: Path) -> None:
    database_path = tmp_path / "source-activation-vertical.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)
    root = Path(__file__).parents[2]
    with Session(engine) as session:
        seed = json.loads((root / "fixtures/profile_seed.json").read_text())
        profile_json = {
            **seed["profile_json"],
            "title": "Platform Engineer",
            "target_roles": ["platform"],
            "target_titles": ["platform engineer"],
            "regions": ["argentina"],
        }
        profile = ProfileRepository(session).create_v1(
            name="offline-campaign-profile",
            profile_json=profile_json,
        )
        discovery_policy = DiscoveryPolicyV1.model_validate(
            {
                "schema_version": 1,
                "policy_version": "campaign-offline-v1",
                "profile_binding": {
                    "profile_id": profile.id,
                    "row_version": profile.version,
                    "schema_version": profile.schema_version,
                    "canonical_profile_sha256": canonical_profile_sha256(profile_json),
                },
                "phrase_grammar": DiscoveryPhraseGrammarV1().model_dump(mode="json"),
                "groups": {"platform": ("Platform Engineer",)},
                "target_roles": {"platform": {"primary_groups": ["platform"]}},
                "target_titles": {
                    "platform engineer": {"primary_groups": ["platform"]}
                },
            }
        )
        SourceRepository(session).create(
            type=SourceType.GREENHOUSE,
            name="Acme",
            configuration={"board_token": "acme", "company": "Acme"},
        )
        SourceActivationCampaignService(session).create(
            profile_id=profile.id,
            created_since=datetime.now(UTC) - timedelta(minutes=1),
            source_types=[SourceType.GREENHOUSE.value],
            batch_size=1,
            expected_managed=1,
        )
        created = SourceActivationCampaignService(session).tick(
            schedule_slot="source-campaign-6h:2026-09-28T00:00:00-03:00"
        )
        run = session.get(JobSearchRun, created["run_id"])
        assert run is not None
        assert run.notification_mode is NotificationMode.MATCH_ALERTS
        assert run.discovery_mode.value == "scheduled_due"
        session.commit()
        run_id = run.id

    search_provider = SearchProvider()

    class DiscoveryCollector:
        async def collect(
            self, snapshot: SourceSnapshot, _runtime: CollectorRuntime
        ) -> CollectionSuccess:
            assert snapshot.source_key == "greenhouse:newco"
            return CollectionSuccess(
                status="ok",
                jobs=(
                    RawJob(
                        source="greenhouse",
                        external_id="discovery-argentina-platform-1",
                        source_url="https://boards.greenhouse.io/newco/jobs/456",
                        application_url="https://boards.greenhouse.io/newco/jobs/456",
                        title="Platform Engineer",
                        company="NewCo",
                        location="Remote Argentina",
                        description="Build the platform from Argentina.",
                        structured_data={
                            "remote_policy": "remote",
                            "regions": ["argentina"],
                            "employment_type": "full_time",
                        },
                        published_at=datetime.now(UTC) - timedelta(days=1),
                        collected_at=datetime.now(UTC),
                    ),
                ),
                metrics=CollectionMetrics(provider_items=1, accepted_items=1),
            )

    class Collector:
        async def collect(
            self, snapshot: SourceSnapshot, _runtime: CollectorRuntime
        ) -> CollectionSuccess:
            assert snapshot.name == "Acme"
            return CollectionSuccess(
                status="ok",
                jobs=(
                    RawJob(
                        source="greenhouse",
                        external_id="argentina-compatible-1",
                        source_url="https://boards.greenhouse.io/acme/jobs/123",
                        application_url="https://boards.greenhouse.io/acme/jobs/123",
                        title="Platform Engineer",
                        company="Acme",
                        location="Remote Argentina",
                        description="Build APIs for the platform team.",
                        structured_data={
                            "remote_policy": "remote",
                            "regions": ["argentina"],
                            "employment_type": "full_time",
                        },
                        published_at=datetime.now(UTC) - timedelta(days=1),
                        collected_at=datetime.now(UTC),
                    ),
                    RawJob(
                        source="greenhouse",
                        external_id="us-only-incompatible-1",
                        source_url="https://boards.greenhouse.io/acme/jobs/124",
                        application_url="https://boards.greenhouse.io/acme/jobs/124",
                        title="Platform Engineer US-only control",
                        company="Acme",
                        location="Remote United States",
                        description="Build APIs for the platform team.",
                        structured_data={
                            "remote_policy": "remote",
                            "employment_type": "full_time",
                        },
                        collected_at=datetime.now(UTC),
                    ),
                ),
                metrics=CollectionMetrics(provider_items=2, accepted_items=2),
            )

    gateway = AcceptedGateway()
    pipeline = Pipeline(
        factory,
        provider=FakeLLMProvider(fixture=root / "fixtures/extraction_valid.json"),
        collector_factory=lambda _snapshot: Collector(),
        discovery_provider=search_provider,
        discovery_collector_factory=lambda _snapshot: DiscoveryCollector(),
        discovery_query_key_secret=b"0123456789abcdef0123456789abcdef",
        discovery_policy_v1=discovery_policy,
        notification_gateway=gateway,
        notification_recipient="offline-test-recipient",
        settings=Settings(environment="dev", telegram_max_attempts=1),
    )
    result = asyncio.run(pipeline.run(run_id))

    assert result.status is JobSearchRunStatus.COMPLETED, (
        result.error_code,
        {
            source_id: result_json.get("error_code")
            for source_id, result_json in result.source_results_json.items()
        },
    )
    assert len(gateway.requests) == 1
    assert "New Role Radar matches" in gateway.requests[0].body
    assert "Daily digest" not in gateway.requests[0].body
    assert "Platform Engineer" in gateway.requests[0].body
    assert "Argentina" in gateway.requests[0].body
    assert "work-authorization guarantee" in gateway.requests[0].body
    assert "US-only control" not in gateway.requests[0].body
    assert "NewCo" in gateway.requests[0].body
    assert "Published" in gateway.requests[0].body
    assert "Apply" in gateway.requests[0].body
    with Session(engine) as session:
        cycle = session.scalar(select(DiscoveryCycle).where(DiscoveryCycle.run_id == run_id))
        discovered = session.scalar(
            select(Source).where(Source.management_origin == "discovery")
        )
        assert cycle is not None
        assert cycle.status is DiscoveryCycleStatus.COMPLETED
        assert cycle.stats_json["verified_sources"] == 1
        assert cycle.stats_json["verified_jobs"] == 1
        assert discovered is not None
        replayed_campaign_run = SourceActivationCampaignService(session).tick(
            schedule_slot="source-campaign-6h:2026-09-28T00:00:00-03:00"
        )
        assert replayed_campaign_run["run_id"] == run_id
        assert len(search_provider.requests) == 4
        next_campaign_run = SourceActivationCampaignService(session).tick(
            schedule_slot="source-campaign-6h:2026-09-28T06:00:00-03:00"
        )
        assert next_campaign_run["run_id"] != run_id
        assert session.scalar(
            select(SourceActivationMember).where(
                SourceActivationMember.source_id == discovered.id
            )
        ) is not None
        next_run = session.get(JobSearchRun, next_campaign_run["run_id"])
        assert next_run is not None
        assert discovered.id in str(next_run.source_snapshot_json)
        assert len(search_provider.requests) == 4

    replay = NotificationService(factory).prepare(
        run_id, recipient_key="offline-test-recipient"
    )
    assert len(replay) == 1
    with Session(engine) as session:
        persisted = session.get(JobSearchRun, run_id)
        assert persisted is not None
        assert persisted.stats_json["new_jobs"] == 1
        run_jobs = list(session.scalars(select(RunJob).where(RunJob.run_id == run_id)))
        assert len({run_job.job_id for run_job in run_jobs}) == 2
        batch = session.scalar(
            select(NotificationBatch).where(NotificationBatch.run_id == run_id)
        )
        assert batch is not None
        assert batch.status is NotificationBatchStatus.SENT
        batches = list(
            session.scalars(select(NotificationBatch).where(NotificationBatch.run_id == run_id))
        )
        items = list(
            session.scalars(select(NotificationItem).where(NotificationItem.run_id == run_id))
        )
        assert len(batches) == 1
        assert len(items) == 2
    engine.dispose()
