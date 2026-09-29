from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from role_radar.db.models import (
    CandidateProfile,
    JobSearchRun,
    Source,
)
from role_radar.discovery.contracts import GreenhouseOfficialCandidate
from role_radar.domain.enums import JobSearchRunStatus, SourceType
from role_radar.repositories.source_activation import SourceActivationCampaignRepository
from role_radar.repositories.sources import SourceRepository
from role_radar.services.discovered_source_service import DiscoveredSourceService
from role_radar.services.source_activation import SourceActivationCampaignService
from role_radar.sources.identity import greenhouse_source_key


def _profile(db_session) -> str:
    profile_id = str(uuid4())
    db_session.add(
        CandidateProfile(
            id=profile_id,
            name="coverage-test",
            version=1,
            schema_version=1,
            profile_json={},
            is_active=True,
        )
    )
    db_session.flush()
    return profile_id


def _greenhouse(
    db_session,
    token: str,
    *,
    management_origin: str = "manual",
    enabled: bool = True,
) -> str:
    return SourceRepository(db_session).create_row(
        source_id=str(uuid4()),
        source_type=SourceType.GREENHOUSE,
        name=f"Greenhouse {token}",
        source_key=greenhouse_source_key(token),
        configuration={"board_token": token},
        configuration_version=1,
        enabled=enabled,
        management_origin=management_origin,
        discovery_policy_version="test-v1" if management_origin == "discovery" else None,
        discovery_verified_at=datetime.now(UTC) if management_origin == "discovery" else None,
    ).id


def _campaign(db_session, *, profile_id: str, batch_size: int, source_count: int):
    service = SourceActivationCampaignService(db_session)
    created_since = datetime.now(UTC) - timedelta(minutes=1)
    return service.create(
        profile_id=profile_id,
        created_since=created_since,
        source_types=[SourceType.GREENHOUSE.value],
        batch_size=batch_size,
        expected_managed=source_count,
    )


def _complete_empty_run(db_session, run_id: str) -> None:
    run = db_session.get(JobSearchRun, run_id)
    assert run is not None
    run.status = JobSearchRunStatus.COMPLETED
    run.source_results_json = {
        item["source_id"]: {"status": "ok", "metrics": {"new_jobs": 0, "duplicates": 0}}
        for item in run.source_snapshot_json or []
    }
    SourceActivationCampaignService(db_session).finalize_run(run_id)
    db_session.flush()


def test_fair_rotation_keeps_empty_healthy_sources_enabled(db_session) -> None:
    profile_id = _profile(db_session)
    for index in range(4):
        _greenhouse(db_session, f"board-{index}")
    _campaign(db_session, profile_id=profile_id, batch_size=2, source_count=4)
    service = SourceActivationCampaignService(db_session)

    first = service.tick(schedule_slot="cycle-1")
    first_run = db_session.get(JobSearchRun, first["run_id"])
    assert first_run is not None
    first_ids = [item["source_id"] for item in first_run.source_snapshot_json]
    _complete_empty_run(db_session, first["run_id"])

    second = service.tick(schedule_slot="cycle-2")
    second_run = db_session.get(JobSearchRun, second["run_id"])
    second_ids = [item["source_id"] for item in second_run.source_snapshot_json]
    _complete_empty_run(db_session, second["run_id"])

    assert set(first_ids).isdisjoint(second_ids)
    members = SourceActivationCampaignRepository(db_session).members(
        first["campaign_id"]
    )
    assert all(member.state == "retained" for member in members)
    assert all(member.no_signal_streak == 1 for member in members)
    assert all(db_session.get(Source, member.source_id).enabled for member in members)


def test_new_verified_board_is_enrolled_and_covered(db_session) -> None:
    profile_id = _profile(db_session)
    _greenhouse(db_session, "existing")
    _campaign(db_session, profile_id=profile_id, batch_size=2, source_count=1)

    discovered = DiscoveredSourceService(db_session, max_new_per_run=100)
    registration = discovered.register_verified(
        GreenhouseOfficialCandidate("https://boards.greenhouse.io/new-board", "new-board")
    )
    assert registration.created and registration.source_id

    # A repeated logical slot must not mutate the first run's frozen snapshot.
    first = SourceActivationCampaignService(db_session).tick(schedule_slot="cycle-1")
    first_run = db_session.get(JobSearchRun, first["run_id"])
    snapshot_before_replay = list(first_run.source_snapshot_json)
    _complete_empty_run(db_session, first["run_id"])
    replay = SourceActivationCampaignService(db_session).tick(schedule_slot="cycle-1")

    assert replay["result"] == "reused"
    assert replay["run_id"] == first["run_id"]
    assert first_run.source_snapshot_json == snapshot_before_replay

    # The newly registered board joins the cohort and is covered next slot.
    tick = SourceActivationCampaignService(db_session).tick(schedule_slot="cycle-2")
    members = SourceActivationCampaignRepository(db_session).members(tick["campaign_id"])
    run = db_session.get(JobSearchRun, tick["run_id"])

    assert len(members) == 2
    assert any(member.source_id == registration.source_id for member in members)
    assert registration.source_id in {item["source_id"] for item in run.source_snapshot_json}


def test_transient_failures_do_not_remove_verified_source_from_rotation(db_session) -> None:
    profile_id = _profile(db_session)
    source_id = _greenhouse(db_session, "transient-error")
    campaign = _campaign(db_session, profile_id=profile_id, batch_size=1, source_count=1)
    service = SourceActivationCampaignService(db_session)

    first = service.tick(schedule_slot="failure-1")
    run = db_session.get(JobSearchRun, first["run_id"])
    run.status = JobSearchRunStatus.FAILED
    run.source_results_json = {source_id: {"status": "failed"}}
    service.finalize_run(run.id)
    second = service.tick(schedule_slot="failure-2")
    second_run = db_session.get(JobSearchRun, second["run_id"])
    second_run.status = JobSearchRunStatus.FAILED
    second_run.source_results_json = {source_id: {"status": "failed"}}
    service.finalize_run(second_run.id)

    member = SourceActivationCampaignRepository(db_session).members(campaign["campaign_id"])[0]
    assert second["managed_selected"] == 1
    assert member.state == "retained"
    assert member.failure_streak == 2
    assert db_session.get(Source, source_id).enabled
    assert SourceActivationCampaignService(db_session).status()["counts"] == {
        "pending": 0,
        "retained": 1,
    }


def test_campaign_creation_excludes_sources_already_disabled(db_session) -> None:
    profile_id = _profile(db_session)
    enabled_id = _greenhouse(db_session, "enabled")
    disabled_id = _greenhouse(db_session, "disabled-at-create", enabled=False)

    campaign = _campaign(db_session, profile_id=profile_id, batch_size=2, source_count=1)
    tick = SourceActivationCampaignService(db_session).tick(schedule_slot="disabled-create")
    run = db_session.get(JobSearchRun, tick["run_id"])
    members = SourceActivationCampaignRepository(db_session).members(campaign["campaign_id"])

    assert tick["managed_selected"] == 1
    assert {member.source_id for member in members} == {enabled_id}
    assert {item["source_id"] for item in run.source_snapshot_json} == {enabled_id}
    assert not db_session.get(Source, disabled_id).enabled


def test_campaign_skips_member_disabled_after_enrollment(db_session) -> None:
    profile_id = _profile(db_session)
    disabled_id = _greenhouse(db_session, "disabled-after-enrollment")
    enabled_id = _greenhouse(db_session, "still-enabled")
    campaign = _campaign(db_session, profile_id=profile_id, batch_size=2, source_count=2)
    db_session.get(Source, disabled_id).enabled = False

    tick = SourceActivationCampaignService(db_session).tick(schedule_slot="disabled-later")
    run = db_session.get(JobSearchRun, tick["run_id"])
    members = SourceActivationCampaignRepository(db_session).members(campaign["campaign_id"])

    assert tick["managed_selected"] == 1
    assert {item["source_id"] for item in run.source_snapshot_json} == {enabled_id}
    assert disabled_id in {member.source_id for member in members}
    assert not db_session.get(Source, disabled_id).enabled


def test_discovery_registration_has_no_lifetime_active_source_cap(db_session) -> None:
    service = DiscoveredSourceService(db_session, max_new_per_run=100)

    registrations = [
        service.register_verified(
            GreenhouseOfficialCandidate(
                f"https://boards.greenhouse.io/board-{index}", f"board-{index}"
            ),
            new_sources_used=index,
        )
        for index in range(55)
    ]

    assert all(item.created and not item.blocked for item in registrations)
    assert len({item.source_id for item in registrations}) == 55
